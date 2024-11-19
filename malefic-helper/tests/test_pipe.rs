use std::path::Path;
use std::{fs, io, thread};
use std::fmt::Debug;
use std::io::ErrorKind;
use std::time::Duration;
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
use malefic_helper::win::pipe::NamedPipe;

#[test]
fn test_create_named_pipe() {
    let pipe = NamedPipe::create(r"\\.\pipe\testpipe").expect("Failed to create named pipe");
    assert!(pipe.handle != INVALID_HANDLE_VALUE);
    pipe.close();
}

#[test]
fn test_open_named_pipe() {
    // 首先创建一个管道
    let server_pipe = NamedPipe::create(r"\\.\pipe\testpipe").expect("Failed to create server pipe");

    // 在另一个线程中等待客户端连接
    thread::spawn(move || {
        server_pipe.wait().expect("Failed to wait for connection");
        server_pipe.close();
    });

    // 模拟客户端连接
    thread::sleep(Duration::from_millis(100));
    let client_pipe = NamedPipe::open(r"\\.\pipe\testpipe").expect("Failed to open client pipe");
    assert!(client_pipe.handle != INVALID_HANDLE_VALUE);
    client_pipe.close();
}

#[test]
fn test_read_write_named_pipe() {
    let server_pipe = NamedPipe::create(r"//.//pipe//bbb").expect("Failed to create server pipe");

    // 在另一个线程中等待客户端写入数据
    thread::spawn(move || {
        server_pipe.wait().expect("Failed to wait for connection");

        let mut buffer = [0u8; 512];
        let bytes_read = server_pipe.read(&mut buffer).expect("Failed to read from pipe");
        assert_eq!(bytes_read, 11);  // 预期读取11个字节
        server_pipe.close();
    });

    // 模拟客户端写入数据
    thread::sleep(Duration::from_millis(100));
    let client_pipe = NamedPipe::open(r"//.//pipe//bbb").expect("Failed to open client pipe");
    let message = b"Hello Pipe";
    let bytes_written = client_pipe.write(message).expect("Failed to write to pipe");
    assert_eq!(bytes_written, message.len() as u32);  // 预期写入消息的长度
    client_pipe.close();
}


#[test]
fn test_write_named_pipe() {
    let server_pipe = NamedPipe::create(r"//.//pipe//bbb").expect("Failed to create server pipe");
    thread::sleep(Duration::from_millis(100));
    server_pipe.wait().expect("Failed to wait for connection");
    // 模拟客户端写入数据
    thread::sleep(Duration::from_millis(100));
    
    let message = b"Hello Pipe";
    let bytes_written = server_pipe.write(message).expect("Failed to write to pipe");
    println!("succ");
    assert_eq!(bytes_written, message.len() as u32);  // 预期写入消息的长度
    println!("succ");
    server_pipe.close();
}

#[test]
fn test_read_named_pipe() {
    let server_pipe = NamedPipe::open(r"//.//pipe//bbb").expect("Failed to create server pipe");
    thread::sleep(Duration::from_millis(100));
    
    let mut buffer = [0u8; 512];
    let bytes_read = server_pipe.read(&mut buffer).expect("Failed to read from pipe");
    assert_eq!(bytes_read, 11);  // 预期读取11个字节
    server_pipe.close();
}


pub fn list_pipes(path: &str) -> io::Result<Vec<String>> {
    let dir = Path::new(path);
    if !dir.exists() || !dir.is_dir() {
        return Err(io::Error::new(ErrorKind::NotFound, "Directory not found"));
    }

    let mut pipes = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        println!("{:?}", entry.metadata()?);
        pipes.push(entry.path().to_string_lossy().to_string());
    }
    Ok(pipes)
}

#[test]
fn test_disconnect_named_pipe() {
    println!("{:#?}", list_pipes("//.//pipe//"));
    let pipe = NamedPipe::create(r"\\.\pipe\testpipe").expect("Failed to create named pipe");
    pipe.disconnect().expect("Failed to disconnect named pipe");
    pipe.close();
}
