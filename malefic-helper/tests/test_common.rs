use malefic_helper::common::net::{get_netstat, get_network_interfaces};

#[test]
pub fn test_interface() {
    println!("{:?}", get_network_interfaces());
}

#[test]
pub fn test_netstat() {
    println!("{:?}", get_netstat());
}