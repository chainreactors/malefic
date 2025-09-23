use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use nix::sys::socket::{SockaddrStorage, SockaddrLike};
use crate::common::net::NetInterface;
use crate::{CommonError, to_error};
use crate::debug;

/// Get all network interfaces with basic information (Linux)
pub fn get_network_interfaces() -> Result<Vec<NetInterface>, CommonError> {
    let mut interfaces = std::collections::HashMap::new();
    
    let addrs = to_error!(getifaddrs())?;
    
    for (index, addr) in addrs.enumerate() {
        let name = addr.interface_name.clone();
        let flags = addr.flags;
        
        // Skip loopback interfaces
        if flags.contains(InterfaceFlags::IFF_LOOPBACK) {
            continue;
        }
        
        // Skip interfaces that are down
        if !flags.contains(InterfaceFlags::IFF_UP) {
            continue;
        }
        
        let entry = interfaces.entry(name.clone()).or_insert_with(|| {
            NetInterface {
                index: index as u32,
                name: name.clone(),
                mac: String::new(),
                ips: Vec::new(),
            }
        });
        
        if let Some(sockaddr) = addr.address {
            if let Some(ip_addr) = extract_ip_from_sockaddr(sockaddr) {
                entry.ips.push(ip_addr.to_string());
            }
        }
    }
    
    // Get MAC addresses
    for (name, interface) in interfaces.iter_mut() {
        interface.mac = get_mac_address(name);
    }
    
    let result: Vec<NetInterface> = interfaces.into_values().collect();
    debug!("Found {} network interfaces", result.len());
    Ok(result)
}

/// Get only IPv4 addresses (non-loopback)
pub fn get_ipv4_addresses() -> Vec<String> {
    match get_network_interfaces() {
        Ok(interfaces) => {
            let mut ipv4_addresses = Vec::new();
            for interface in interfaces {
                for ip_str in interface.ips {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if let IpAddr::V4(ipv4) = ip {
                            ipv4_addresses.push(ipv4.to_string());
                        }
                    }
                }
            }
            ipv4_addresses
        }
        Err(e) => {
            debug!("Failed to get IPv4 addresses: {}", e);
            Vec::new()
        }
    }
}

/// Legacy method for compatibility
pub fn get_ip_addresses() -> Vec<String> {
    get_ipv4_addresses().into_iter()
        .map(|ip| ip.to_string())
        .collect()
}

/// Extract IP address from sockaddr
fn extract_ip_from_sockaddr(sockaddr: SockaddrStorage) -> Option<IpAddr> {
    match sockaddr.family() {
        Some(nix::sys::socket::AddressFamily::Inet) => {
            if let Some(inet_addr) = sockaddr.as_sockaddr_in() {
                let ip = inet_addr.ip();
                return Some(IpAddr::V4(Ipv4Addr::from(ip)));
            }
        }
        Some(nix::sys::socket::AddressFamily::Inet6) => {
            if let Some(inet6_addr) = sockaddr.as_sockaddr_in6() {
                let ip = inet6_addr.ip();
                return Some(IpAddr::V6(Ipv6Addr::from(ip)));
            }
        }
        _ => {}
    }
    None
}

/// Get MAC address using the mac_address crate (cross-platform and reliable)
fn get_mac_address(interface_name: &str) -> String {
    match mac_address::mac_address_by_name(interface_name) {
        Ok(Some(mac)) => {
            format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac.bytes()[0], mac.bytes()[1], mac.bytes()[2],
                mac.bytes()[3], mac.bytes()[4], mac.bytes()[5])
        }
        _ => {
            // Fallback to Linux sysfs method
            get_mac_address_sysfs(interface_name)
        }
    }
}

/// Fallback method using Linux sysfs
fn get_mac_address_sysfs(interface: &str) -> String {
    use std::fs;
    let path = format!("/sys/class/net/{}/address", interface);
    fs::read_to_string(path)
        .ok()
        .map(|content| content.trim().to_string())
        .filter(|mac| mac != "00:00:00:00:00:00")
        .unwrap_or_else(String::new)
}


