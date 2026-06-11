/// Icon replacement logic for PE files.
///
/// Strategy: in-place replacement.
/// - Parse the ICO file to get individual icon images.
/// - Parse the PE resource directory to find RT_ICON and RT_GROUP_ICON entries.
/// - For each icon image: if new data fits within existing allocation, overwrite in-place.
/// - Update RT_GROUP_ICON to match the new icon entries.
/// - If new icon data is larger than existing allocation, return an error.
use anyhow::{anyhow, Result};

use super::ico_parser::{parse_ico, IcoFile};
use super::resource::{
    find_group_icon_entries, find_rsrc_section, parse_grp_icon_dir, parse_resource_directory,
};

/// Replace the icon in a PE file with the icon from an ICO file.
pub fn replace_icon(pe_path: &str, ico_path: &str, output_path: &str) -> Result<()> {
    let ico_data = std::fs::read(ico_path)
        .map_err(|e| anyhow!("Failed to read ICO file '{}': {}", ico_path, e))?;
    let ico = parse_ico(&ico_data)?;

    let pe_data = std::fs::read(pe_path)
        .map_err(|e| anyhow!("Failed to read PE file '{}': {}", pe_path, e))?;

    let rsrc_info = find_rsrc_section(&pe_data)?;

    // Extract .rsrc section data
    let rsrc_start = rsrc_info.file_offset as usize;
    let rsrc_end = rsrc_start + rsrc_info.raw_size as usize;
    if rsrc_end > pe_data.len() {
        return Err(anyhow!(".rsrc section extends beyond file"));
    }
    let rsrc_data = &pe_data[rsrc_start..rsrc_end];

    // Parse resource directory tree
    let resource_tree = parse_resource_directory(rsrc_data, &rsrc_info)?;

    // Find existing group icon entries to determine icon IDs
    let group_icon_entries = find_group_icon_entries(&resource_tree);
    if group_icon_entries.is_empty() {
        return Err(anyhow!(
            "No RT_GROUP_ICON entries found in PE resource directory"
        ));
    }
    let grp_entry = group_icon_entries[0];
    let grp_data_offset = grp_entry.data_file_offset as usize;
    let grp_data_size = grp_entry.size as usize;

    if grp_data_offset + grp_data_size > pe_data.len() {
        return Err(anyhow!("RT_GROUP_ICON data out of bounds"));
    }
    let grp_data = &pe_data[grp_data_offset..grp_data_offset + grp_data_size];
    let existing_grp_entries = parse_grp_icon_dir(grp_data)?;

    // Create a map of icon ID -> data entry info for existing icons
    // The icon entries are nested: RT_ICON -> name -> language -> data
    // We need to match by traversing the tree
    let mut icon_data_map: Vec<(u16, u64, u32)> = Vec::new(); // (id, file_offset, existing_size)
    for grp_e in &existing_grp_entries {
        // Find the matching RT_ICON entry by traversing the tree
        for type_entry in &resource_tree {
            if type_entry.id == super::resource::RT_ICON {
                for name_entry in &type_entry.children {
                    if name_entry.id == grp_e.id as u32 {
                        // Descend to language level
                        for lang_entry in &name_entry.children {
                            if let Some(ref data) = lang_entry.data {
                                icon_data_map.push((grp_e.id, data.data_file_offset, data.size));
                            }
                        }
                        // Also check if name_entry itself has data (2-level tree)
                        if let Some(ref data) = name_entry.data {
                            icon_data_map.push((grp_e.id, data.data_file_offset, data.size));
                        }
                    }
                }
            }
        }
    }

    // Sort by ID
    icon_data_map.sort_by_key(|&(id, _, _)| id);
    icon_data_map.dedup_by_key(|e| e.0);

    // Now replace: copy PE data, overwrite icon data in-place
    let mut output_data = pe_data.clone();

    let num_to_replace = ico.entries.len().min(icon_data_map.len());

    for i in 0..num_to_replace {
        let (_existing_id, file_offset, existing_size) = icon_data_map[i];
        let new_data = &ico.image_data[i];

        if new_data.len() > existing_size as usize {
            return Err(anyhow!(
                "New icon image {} is {} bytes but existing slot is only {} bytes. \
                 Icon must be same size or smaller than the original.",
                i,
                new_data.len(),
                existing_size
            ));
        }

        let offset = file_offset as usize;
        // Write new icon data
        output_data[offset..offset + new_data.len()].copy_from_slice(new_data);
        // Zero-fill remaining space
        for j in new_data.len()..existing_size as usize {
            output_data[offset + j] = 0;
        }

        // Update the resource data entry's Size field to match new data size
        // Find the corresponding data entry and update its size in the .rsrc section
        for type_entry in &resource_tree {
            if type_entry.id == super::resource::RT_ICON {
                for name_entry in &type_entry.children {
                    if name_entry.id == icon_data_map[i].0 as u32 {
                        for lang_entry in &name_entry.children {
                            if let Some(ref data) = lang_entry.data {
                                if data.data_file_offset == file_offset {
                                    // Update size at entry_file_offset + 4
                                    let size_offset = data.entry_file_offset as usize + 4;
                                    if size_offset + 4 <= output_data.len() {
                                        let new_size = new_data.len() as u32;
                                        output_data[size_offset..size_offset + 4]
                                            .copy_from_slice(&new_size.to_le_bytes());
                                    }
                                }
                            }
                        }
                        if let Some(ref data) = name_entry.data {
                            if data.data_file_offset == file_offset {
                                let size_offset = data.entry_file_offset as usize + 4;
                                if size_offset + 4 <= output_data.len() {
                                    let new_size = new_data.len() as u32;
                                    output_data[size_offset..size_offset + 4]
                                        .copy_from_slice(&new_size.to_le_bytes());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Build new group icon dir using new ICO entries but existing IDs
    let new_grp_dir = build_replacement_grp_icon_dir(&ico, &existing_grp_entries);
    if new_grp_dir.len() <= grp_data_size {
        let offset = grp_data_offset;
        output_data[offset..offset + new_grp_dir.len()].copy_from_slice(&new_grp_dir);
        // Zero-fill remaining
        for j in new_grp_dir.len()..grp_data_size {
            output_data[offset + j] = 0;
        }
        // Update the group icon data entry size
        let grp_entry_size_offset = grp_entry.entry_file_offset as usize + 4;
        if grp_entry_size_offset + 4 <= output_data.len() {
            let new_size = new_grp_dir.len() as u32;
            output_data[grp_entry_size_offset..grp_entry_size_offset + 4]
                .copy_from_slice(&new_size.to_le_bytes());
        }
    }

    std::fs::write(output_path, &output_data)?;

    Ok(())
}

/// Build a replacement GRPICONDIR that uses existing icon resource IDs.
fn build_replacement_grp_icon_dir(
    ico: &IcoFile,
    existing_entries: &[super::resource::GrpIconDirEntry],
) -> Vec<u8> {
    let count = ico.entries.len().min(existing_entries.len()) as u16;
    let mut buf = Vec::with_capacity(6 + count as usize * 14);

    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&ico.image_type.to_le_bytes()); // type
    buf.extend_from_slice(&count.to_le_bytes()); // count

    for i in 0..count as usize {
        let ico_entry = &ico.entries[i];
        let existing_id = existing_entries[i].id;

        buf.push(ico_entry.width);
        buf.push(ico_entry.height);
        buf.push(ico_entry.color_count);
        buf.push(0); // reserved
        buf.extend_from_slice(&ico_entry.planes.to_le_bytes());
        buf.extend_from_slice(&ico_entry.bit_count.to_le_bytes());
        buf.extend_from_slice(&ico_entry.bytes_in_res.to_le_bytes());
        buf.extend_from_slice(&existing_id.to_le_bytes()); // keep existing resource ID
    }

    buf
}

/// Extract icons from a PE file and save as an ICO file.
pub fn extract_icon(pe_path: &str, output_ico_path: &str) -> Result<()> {
    let pe_data = std::fs::read(pe_path)
        .map_err(|e| anyhow!("Failed to read PE file '{}': {}", pe_path, e))?;

    let rsrc_info = find_rsrc_section(&pe_data)?;
    let rsrc_start = rsrc_info.file_offset as usize;
    let rsrc_end = rsrc_start + rsrc_info.raw_size as usize;
    if rsrc_end > pe_data.len() {
        return Err(anyhow!(".rsrc section extends beyond file"));
    }
    let rsrc_data = &pe_data[rsrc_start..rsrc_end];

    let resource_tree = parse_resource_directory(rsrc_data, &rsrc_info)?;

    // Find RT_GROUP_ICON
    let group_icon_entries = find_group_icon_entries(&resource_tree);
    if group_icon_entries.is_empty() {
        return Err(anyhow!("No RT_GROUP_ICON found"));
    }

    let grp_entry = group_icon_entries[0];
    let grp_data_offset = grp_entry.data_file_offset as usize;
    let grp_data_size = grp_entry.size as usize;
    let grp_data = &pe_data[grp_data_offset..grp_data_offset + grp_data_size];
    let grp_entries = parse_grp_icon_dir(grp_data)?;

    // Collect icon image data using resource IDs
    let mut icon_images: Vec<(u8, u8, u8, u16, u16, Vec<u8>)> = Vec::new();

    for grp_e in &grp_entries {
        // Find matching RT_ICON by id
        for type_entry in &resource_tree {
            if type_entry.id == super::resource::RT_ICON {
                for name_entry in &type_entry.children {
                    if name_entry.id == grp_e.id as u32 {
                        // Get data from language level
                        let data_entry = name_entry
                            .children
                            .iter()
                            .find_map(|lang| lang.data.as_ref())
                            .or(name_entry.data.as_ref());

                        if let Some(de) = data_entry {
                            let start = de.data_file_offset as usize;
                            let end = start + de.size as usize;
                            if end <= pe_data.len() {
                                icon_images.push((
                                    grp_e.width,
                                    grp_e.height,
                                    grp_e.color_count,
                                    grp_e.planes,
                                    grp_e.bit_count,
                                    pe_data[start..end].to_vec(),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    if icon_images.is_empty() {
        return Err(anyhow!("No icon image data found"));
    }

    // Build ICO file
    let count = icon_images.len() as u16;
    let header_size = 6 + count as u32 * 16;
    let mut ico_buf = Vec::new();

    // ICONDIR header
    ico_buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    ico_buf.extend_from_slice(&1u16.to_le_bytes()); // type = ICO
    ico_buf.extend_from_slice(&count.to_le_bytes());

    // Calculate offsets for image data
    let mut current_offset = header_size;
    for (width, height, color_count, planes, bit_count, ref data) in &icon_images {
        ico_buf.push(*width);
        ico_buf.push(*height);
        ico_buf.push(*color_count);
        ico_buf.push(0); // reserved
        ico_buf.extend_from_slice(&planes.to_le_bytes());
        ico_buf.extend_from_slice(&bit_count.to_le_bytes());
        ico_buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        ico_buf.extend_from_slice(&current_offset.to_le_bytes());
        current_offset += data.len() as u32;
    }

    // Image data
    for (_, _, _, _, _, ref data) in &icon_images {
        ico_buf.extend_from_slice(data);
    }

    std::fs::write(output_ico_path, &ico_buf)?;

    Ok(())
}
