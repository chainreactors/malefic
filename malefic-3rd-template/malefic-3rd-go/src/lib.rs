use malefic_3rd_ffi::*;
use std::ffi::{c_char, c_int, c_uint};

extern "C" {
    fn GoModuleName() -> *const c_char;
    fn GoModuleSend(task_id: c_uint, data: *const c_char, data_len: c_int) -> c_int;
    fn GoModuleRecv(task_id: c_uint, out_len: *mut c_int, status: *mut c_int) -> *mut c_char;
    fn GoModuleCloseInput(task_id: c_uint);
}

fn go_send(id: u32, data: &[u8]) -> Result<(), String> {
    let rc = unsafe {
        GoModuleSend(id as c_uint, data.as_ptr() as *const c_char, data.len() as c_int)
    };
    if rc != 0 {
        Err(format!("GoModuleSend failed (task {})", id))
    } else {
        Ok(())
    }
}

fn go_recv_blocking(id: u32) -> Result<Option<Vec<u8>>, String> {
    let mut out_len: c_int = 0;
    let mut status: c_int = 0;
    let ptr = unsafe { GoModuleRecv(id as c_uint, &mut out_len, &mut status) };
    match status {
        0 => {
            if ptr.is_null() {
                return Err("GoModuleRecv returned null with status 0".into());
            }
            let buf = unsafe { FfiBuffer::new(ptr, out_len as usize) };
            Ok(Some(buf.as_bytes().to_vec()))
        }
        1 => Ok(None), // done
        _ => Err(format!("GoModuleRecv error (status={})", status)),
    }
}

pub struct GolangModule {
    name: String,
}

impl RtModule for GolangModule {
    fn name() -> &'static str { "example_go" }

    fn new() -> Self {
        let name = unsafe { ffi_module_name(GoModuleName, true) };
        Self { name }
    }

    fn run(&mut self, id: u32, ch: &RtChannel) -> RtResult {
        let mut last_response: Option<Body> = None;

        // Process incoming requests synchronously.
        // Since run() is already blocking, no need for threads or async.
        loop {
            let body = match ch.recv() {
                Ok(b) => b,
                Err(RtChannelError::Eof) => {
                    // Input closed — close Go input and drain remaining responses.
                    unsafe { GoModuleCloseInput(id as c_uint) };
                    // Drain any remaining Go responses.
                    loop {
                        match go_recv_blocking(id) {
                            Ok(Some(resp_bytes)) => {
                                if let Ok(response) = decode_response(&resp_bytes) {
                                    if let Some(prev) = last_response.take() {
                                        if ch.send(prev).is_err() { break; }
                                    }
                                    last_response = Some(Body::Response(response));
                                }
                            }
                            _ => break,
                        }
                    }
                    break;
                }
                Err(e) => return RtResult::Error(e.to_string()),
            };

            match body {
                Body::Request(request) => {
                    // Encode and send to Go.
                    let buf = match encode_request(&request) {
                        Ok(b) => b,
                        Err(e) => return RtResult::Error(format!("encode: {}", e)),
                    };
                    if let Err(e) = go_send(id, &buf) {
                        return RtResult::Error(e);
                    }

                    // Receive response from Go (blocking).
                    match go_recv_blocking(id) {
                        Ok(Some(resp_bytes)) => {
                            let response = match decode_response(&resp_bytes) {
                                Ok(r) => r,
                                Err(e) => return RtResult::Error(format!("decode: {}", e)),
                            };
                            // Buffer: send previous result, store current.
                            if let Some(prev) = last_response.take() {
                                if ch.send(prev).is_err() { break; }
                            }
                            last_response = Some(Body::Response(response));
                        }
                        Ok(None) => break, // Go module done
                        Err(e) => return RtResult::Error(e),
                    }
                }
                _ => {
                    // Non-request body — close Go input.
                    unsafe { GoModuleCloseInput(id as c_uint) };
                    break;
                }
            }
        }

        match last_response {
            Some(body) => RtResult::Done(body),
            None => RtResult::Error("Go module produced no output".into()),
        }
    }
}
