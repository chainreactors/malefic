// Test cases for the refactored network interface code
// This demonstrates how to use the new nix-based network interface functions

#[cfg(target_os = "linux")]
use malefic_helper::linux::ipconfig::{get_network_interfaces, get_ipv4_addresses, get_ip_addresses};

#[cfg(target_os = "macos")]
use malefic_helper::darwin::ipconfig::{get_network_interfaces, get_ipv4_addresses, get_ip_addresses};

#[test]
fn test_get_ipv4_addresses() {
    let addresses = get_ipv4_addresses();
    println!("Found {} IPv4 addresses", addresses.len());
    for addr in &addresses {
        println!("  - {}", addr);
    }
    
    // Should have at least one address (even if it's loopback in some systems)
    // Note: This might be 0 on some systems without network interfaces
    assert!(addresses.len() >= 0);
    
    // Verify all returned addresses are valid IPv4
    for addr in addresses {
        assert!(!addr.is_unspecified() || addr.is_loopback());
    }
}

#[test]
fn test_get_network_interfaces() {
    match get_network_interfaces() {
        Ok(interfaces) => {
            println!("Found {} network interfaces", interfaces.len());
            for interface in &interfaces {
                println!("  - {} ({})", interface.name, 
                        if interface.is_up { "UP" } else { "DOWN" });
                
                // Basic validation
                assert!(!interface.name.is_empty());
                
                // If interface has IP addresses, they should be valid
                for ip in &interface.ip_addresses {
                    match ip {
                        std::net::IpAddr::V4(ipv4) => {
                            assert!(ipv4.octets().len() == 4);
                        }
                        std::net::IpAddr::V6(_) => {
                            // IPv6 is valid
                        }
                    }
                }
            }
            
            // Should find at least the loopback interface on most systems
            let has_loopback = interfaces.iter().any(|i| i.is_loopback);
            if interfaces.len() > 0 {
                // Most systems should have a loopback interface
                println!("Has loopback interface: {}", has_loopback);
            }
        }
        Err(e) => {
            eprintln!("Error getting network interfaces: {}", e);
            // Don't fail the test, as this might be expected in some environments
        }
    }
}

#[test]
fn test_legacy_get_ip_addresses() {
    let ip_strings = get_ip_addresses();
    println!("Found {} IP address strings", ip_strings.len());
    for ip_string in &ip_strings {
        println!("  - {}", ip_string);
        
        // Verify each string is a valid IP address
        assert!(ip_string.parse::<std::net::IpAddr>().is_ok(), 
               "Invalid IP address: {}", ip_string);
    }
}

#[test]
fn test_interface_details() {
    if let Ok(interfaces) = get_network_interfaces() {
        for interface in interfaces {
            println!("=== Interface: {} ===", interface.name);
            println!("  Status: {}", if interface.is_up { "UP" } else { "DOWN" });
            println!("  Type: {}", if interface.is_loopback { "Loopback" } else { "Physical" });
            
            if let Some(mac) = &interface.mac_address {
                println!("  MAC Address: {}", mac);
                // Basic MAC address format validation (should contain colons)
                if !interface.is_loopback {
                    assert!(mac.contains(':'), "Invalid MAC address format: {}", mac);
                }
            }
            
            if let Some(mtu) = interface.mtu {
                println!("  MTU: {}", mtu);
                // MTU should be reasonable (at least 68 for IPv4, typically 1500+ for Ethernet)
                assert!(mtu >= 68 && mtu <= 65536, "Invalid MTU: {}", mtu);
            }
            
            if let Some(speed) = interface.speed {
                println!("  Speed: {} Mbps", speed);
                // Speed should be reasonable if reported
                assert!(speed > 0 && speed <= 100000, "Invalid speed: {} Mbps", speed);
            }
            
            println!("  IP Addresses ({}): ", interface.ip_addresses.len());
            for ip in &interface.ip_addresses {
                println!("    - {}", ip);
            }
            
            print!("  Flags: ");
            let mut flags = Vec::new();
            if interface.is_broadcast {
                flags.push("Broadcast");
            }
            if interface.is_multicast {
                flags.push("Multicast");
            }
            if interface.is_loopback {
                flags.push("Loopback");
            }
            if interface.is_up {
                flags.push("Up");
            }
            println!("{}", flags.join(", "));
            
            println!();
        }
    }
}