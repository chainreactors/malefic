#[derive(Debug, Clone)]
pub struct PEInfo {
    // PE header location
    pub pe_header_location: u32,

    // COFF Header fields
    pub machine_type: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,

    // Optional Header fields
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>, // Only in PE32
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,

    // Data Directories
    pub export_table_rva: u32,
    pub export_table_size: u32,
    pub import_table_rva: u32,
    pub import_table_size: u32,

    // Certificate Table
    pub cert_table_location: u32, // File offset to cert table entry
    pub cert_location: u32,       // File offset to actual certificate data
    pub cert_size: u32,           // Size of certificate data
}

impl PEInfo {
    pub fn new() -> Self {
        Self {
            pe_header_location: 0,
            machine_type: 0,
            number_of_sections: 0,
            time_date_stamp: 0,
            size_of_optional_header: 0,
            characteristics: 0,
            magic: 0,
            major_linker_version: 0,
            minor_linker_version: 0,
            size_of_code: 0,
            size_of_initialized_data: 0,
            size_of_uninitialized_data: 0,
            address_of_entry_point: 0,
            base_of_code: 0,
            base_of_data: None,
            image_base: 0,
            section_alignment: 0,
            file_alignment: 0,
            major_os_version: 0,
            minor_os_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 0,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0,
            size_of_headers: 0,
            checksum: 0,
            subsystem: 0,
            dll_characteristics: 0,
            size_of_stack_reserve: 0,
            size_of_stack_commit: 0,
            size_of_heap_reserve: 0,
            size_of_heap_commit: 0,
            loader_flags: 0,
            number_of_rva_and_sizes: 0,
            export_table_rva: 0,
            export_table_size: 0,
            import_table_rva: 0,
            import_table_size: 0,
            cert_table_location: 0,
            cert_location: 0,
            cert_size: 0,
        }
    }

    pub fn is_signed(&self) -> bool {
        self.cert_location != 0 && self.cert_size != 0
    }

    pub fn is_pe32_plus(&self) -> bool {
        self.magic == 0x20B
    }
}
