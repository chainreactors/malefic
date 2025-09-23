use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME
};
use windows::Win32::Networking::WinSock::{AF_INET, /* AF_INET6, */ SOCKADDR_IN, /* SOCKADDR_IN6 */};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use crate::debug;

/// Get IPv4 addresses for all network adapters
/// Note: IPv6 addresses are currently commented out and not included in the result
pub fn get_ipv4_addresses() -> Vec<String> {
    let mut addresses = Vec::new();
    let mut buffer_size: u32 = 0;

    // First call to get the required buffer size
    let result = unsafe {
        GetAdaptersAddresses(
            AF_INET.0 as u32,
            GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
            None,
            None,
            &mut buffer_size
        )
    };

    if result != ERROR_BUFFER_OVERFLOW.0 {
        debug!("GetAdaptersAddresses first call failed: {}", result);
        return addresses;
    }

    // Allocate buffer
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
    let adapter_addresses = buffer.as_mut_ptr() as *mut windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;

    // Second call to get actual data
    let result = unsafe {
        GetAdaptersAddresses(
            AF_INET.0 as u32,
            GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
            None,
            Some(adapter_addresses),
            &mut buffer_size
        )
    };

    if result != ERROR_SUCCESS.0 {
        debug!("GetAdaptersAddresses second call failed: {}", result);
        return addresses;
    }

    // Iterate through all adapters
    let mut current_adapter = adapter_addresses;
    while !current_adapter.is_null() {
        let adapter = unsafe { &*current_adapter };

        // Iterate through all unicast addresses of current adapter
        let mut current_unicast = adapter.FirstUnicastAddress;
        while !current_unicast.is_null() {
            let unicast = unsafe { &*current_unicast };

            // Get IP address
            if let Some(ip_str) = sockaddr_to_string(unicast.Address.lpSockaddr) {
                addresses.push(ip_str);
            }

            current_unicast = unicast.Next;
        }

        current_adapter = adapter.Next;
    }

    addresses
}

/// Convert SOCKADDR to string format IP address
fn sockaddr_to_string(sockaddr: *const windows::Win32::Networking::WinSock::SOCKADDR) -> Option<String> {
    if sockaddr.is_null() {
        return None;
    }

    unsafe {
        let sa_family = (*sockaddr).sa_family;
        match sa_family {
            AF_INET => {
                let sockaddr_in = sockaddr as *const SOCKADDR_IN;
                let addr = (*sockaddr_in).sin_addr;
                let ip_bytes = addr.S_un.S_addr.to_le_bytes();
                Some(format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]))
            }
            // AF_INET6 => {
            //     let sockaddr_in6 = sockaddr as *const SOCKADDR_IN6;
            //     let addr = (*sockaddr_in6).sin6_addr;
            //     let ip_bytes = addr.u.Byte;
            //     // IPv6 address formatting (simplified, shows first 8 bytes)
            //     Some(format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            //         u16::from_be_bytes([ip_bytes[0], ip_bytes[1]]),
            //         u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]),
            //         u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]),
            //         u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]),
            //         u16::from_be_bytes([ip_bytes[8], ip_bytes[9]]),
            //         u16::from_be_bytes([ip_bytes[10], ip_bytes[11]]),
            //         u16::from_be_bytes([ip_bytes[12], ip_bytes[13]]),
            //         u16::from_be_bytes([ip_bytes[14], ip_bytes[15]])
            //     ))
            // }
            _ => None
        }
    }
}
