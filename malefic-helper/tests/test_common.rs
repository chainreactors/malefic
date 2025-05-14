use malefic_helper::common::net::{get_netstat, get_network_interfaces};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

#[test]
pub fn test_interface() {
    println!("{:?}", get_network_interfaces());
}

#[test]
pub fn test_netstat() {
    println!("{:?}", get_netstat());
}

#[test]
pub fn test_netstat_with_connections() {
    // 创建 TCP 监听器
    let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    
    // 创建 TCP 连接
    let tcp_handle = thread::spawn(move || {
        let _stream = TcpStream::connect(format!("127.0.0.1:{}", tcp_port)).unwrap();
        thread::sleep(Duration::from_secs(1));
    });

    // 创建 UDP socket
    let udp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    
    // 等待连接建立
    thread::sleep(Duration::from_millis(100));

    // 获取所有网络连接
    let netstats = get_netstat().unwrap();
    assert!(!netstats.is_empty(), "Should have network connections");
    
    // 验证 TCP 连接
    let mut found_tcp = false;
    for socket in &netstats {
        if socket.protocol == "tcp" && socket.local_addr.contains(&tcp_port.to_string()) {
            found_tcp = true;
            assert!(!socket.local_addr.is_empty());
            assert!(!socket.remote_addr.is_empty());
            assert!(socket.pid > 0);
        }
    }
    assert!(found_tcp, "Should find our TCP connection");

    // 验证 UDP socket
    let mut found_udp = false;
    for socket in &netstats {
        if socket.protocol == "udp" && socket.local_addr.contains(&udp_port.to_string()) {
            found_udp = true;
            assert!(!socket.local_addr.is_empty());
            assert!(socket.pid > 0);
        }
    }
    assert!(found_udp, "Should find our UDP socket");

    // 等待 TCP 连接完成
    tcp_handle.join().unwrap();
}

#[test]
pub fn test_netstat_ipv6() {
    // 创建 IPv6 TCP 监听器
    let tcp_listener = TcpListener::bind("[::1]:0").unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    
    // 创建 IPv6 TCP 连接
    let tcp_handle = thread::spawn(move || {
        let _stream = TcpStream::connect(format!("[::1]:{}", tcp_port)).unwrap();
        thread::sleep(Duration::from_secs(1));
    });

    // 创建 IPv6 UDP socket
    let udp_socket = UdpSocket::bind("[::1]:0").unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    
    // 等待连接建立
    thread::sleep(Duration::from_millis(100));

    // 获取所有网络连接
    let netstats = get_netstat().unwrap();
    assert!(!netstats.is_empty(), "Should have network connections");
    
    // 验证 IPv6 TCP 连接
    let mut found_tcp6 = false;
    for socket in &netstats {
        if socket.protocol == "tcp" && socket.local_addr.contains(&tcp_port.to_string()) {
            found_tcp6 = true;
            assert!(socket.local_addr.contains("::1"));
            assert!(!socket.local_addr.is_empty());
            assert!(!socket.remote_addr.is_empty());
            assert!(socket.pid > 0);
        }
    }
    assert!(found_tcp6, "Should find our IPv6 TCP connection");

    // 验证 IPv6 UDP socket
    let mut found_udp6 = false;
    for socket in &netstats {
        if socket.protocol == "udp" && socket.local_addr.contains(&udp_port.to_string()) {
            found_udp6 = true;
            assert!(socket.local_addr.contains("::1"));
            assert!(!socket.local_addr.is_empty());
            assert!(socket.pid > 0);
        }
    }
    assert!(found_udp6, "Should find our IPv6 UDP socket");

    // 等待 TCP 连接完成
    tcp_handle.join().unwrap();
}

#[test]
pub fn test_netstat_all_protocols() {
    let netstats = get_netstat().unwrap();
    assert!(!netstats.is_empty(), "Should have network connections");
    
    // 验证所有连接的基本信息
    for netstat in netstats {
        assert!(!netstat.local_addr.is_empty(), "Local address should not be empty");
        assert!(!netstat.protocol.is_empty(), "Protocol should not be empty");
        assert!(netstat.pid > 0, "PID should be greater than 0");
        
        // 验证协议格式
        assert!(
            netstat.protocol == "tcp" || 
            netstat.protocol == "tcp6" || 
            netstat.protocol == "udp" || 
            netstat.protocol == "udp6",
            "Invalid protocol: {}",
            netstat.protocol
        );
        
        // 验证地址格式
        if netstat.protocol.contains("6") {
            assert!(
                netstat.local_addr.contains("::") || 
                netstat.local_addr.contains("[::1]"),
                "Invalid IPv6 address: {}",
                netstat.local_addr
            );
        } else {
            assert!(
                netstat.local_addr.contains("."),
                "Invalid IPv4 address: {}",
                netstat.local_addr
            );
        }
    }
}

#[test]
fn test_get_netstat() {
    let handle = thread::spawn(|| {
        let result = malefic_helper::common::net::get_netstat();
        assert!(result.is_ok(), "Failed to get netstat: {:?}", result.err());
        let connections = result.unwrap();
        assert!(!connections.is_empty(), "No network connections found");
        
        for conn in connections {
            assert!(!conn.local_addr.is_empty(), "Local address should not be empty");
            assert!(!conn.protocol.is_empty(), "Protocol should not be empty");
        }
    });

    match handle.join() {
        Ok(_) => println!("Test completed successfully"),
        Err(_) => panic!("Test failed"),
    }
}

#[test]
fn test_get_sockets() {
    let handle = thread::spawn(|| {
        let result = malefic_helper::darwin::netstat::get_sockets(true, true, true, true);
        assert!(result.is_ok(), "Failed to get sockets: {:?}", result.err());
        let sockets = result.unwrap();
        assert!(!sockets.is_empty(), "No sockets found");
    });

    match handle.join() {
        Ok(_) => println!("Test completed successfully"),
        Err(_) => panic!("Test failed"),
    }
}

#[test]
fn test_tcp_sockets() {
    let handle = thread::spawn(|| {
        let result = malefic_helper::darwin::netstat::get_sockets(true, false, true, false);
        assert!(result.is_ok(), "Failed to get TCP sockets: {:?}", result.err());
        let sockets = result.unwrap();
        assert!(!sockets.is_empty(), "No TCP sockets found");
    });

    match handle.join() {
        Ok(_) => println!("Test completed successfully"),
        Err(_) => panic!("Test failed"),
    }
}