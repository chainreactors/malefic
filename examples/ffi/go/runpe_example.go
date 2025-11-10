package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// RawString represents the return type from the Rust FFI
type RawString struct {
	Data     *byte
	Len      uintptr
	Capacity uintptr
}

func main() {
	// Load the DLL
	dll, err := syscall.LoadDLL("malefic_win_kit.dll")
	if err != nil {
		fmt.Printf("Failed to load DLL: %v\n", err)
		os.Exit(1)
	}
	defer dll.Release()

	// Get RunPE function
	runPEProc, err := dll.FindProc("RunPE")
	if err != nil {
		fmt.Printf("Failed to find RunPE: %v\n", err)
		os.Exit(1)
	}

	// Get SafeFreePipeData function
	safeFreeProc, err := dll.FindProc("SafeFreePipeData")
	if err != nil {
		fmt.Printf("Failed to find SafeFreePipeData: %v\n", err)
		os.Exit(1)
	}

	// Read gogo.exe
	peData, err := os.ReadFile("gogo.exe")
	if err != nil {
		fmt.Printf("Failed to read gogo.exe: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded gogo.exe: %d bytes\n", len(peData))

	// Prepare parameters based on Rust example
	// start_commandline: sacrifice process (e.g., cmd.exe)
	startCmd := []byte("C:\\Windows\\System32\\cmd.exe")

	fmt.Println("Calling RunPE...")

	// Allocate space for the return value
	// In Windows x64 calling convention, structs larger than 8 bytes are returned
	// via a hidden pointer parameter (passed as the first argument in RCX)
	var result RawString

	// Call RunPE with all parameters
	// The first parameter is a pointer to where the return value should be stored
	syscall.SyscallN(
		runPEProc.Addr(),
		uintptr(unsafe.Pointer(&result)),           // Hidden return value pointer (first param)
		uintptr(unsafe.Pointer(&startCmd[0])),      // start_commandline
		uintptr(len(startCmd)),                      // start_commandline_len
		0,                                           // hijack_commandline (nil)
		0,                                           // hijack_commandline_len
		uintptr(unsafe.Pointer(&peData[0])),         // data
		uintptr(len(peData)),                        // data_size
		0,                                           // entrypoint (nil)
		0,                                           // entrypoint_len
		0,                                           // args (nil)
		0,                                           // args_len
		uintptr(0),                                  // is_x86 (false = x64)
		uintptr(0),                                  // pid (0 = create new process)
		uintptr(0),                                  // block_dll (false)
		uintptr(1),                                  // need_output (true)
	)

	fmt.Printf("RunPE returned: data=%p, len=%d, capacity=%d\n",
		result.Data, result.Len, result.Capacity)

	// Convert result to string (similar to String::from_raw_parts in Rust)
	if result.Data != nil && result.Len > 0 {
		// Use unsafe.Slice to create a Go slice from the raw pointer
		output := unsafe.Slice(result.Data, result.Len)
		fmt.Printf("\n=== Output ===\n%s\n=============\n", string(output))

		// Free the memory using SafeFreePipeData
		syscall.SyscallN(safeFreeProc.Addr(), uintptr(unsafe.Pointer(result.Data)))
		fmt.Println("Memory freed")
	} else {
		fmt.Println("No output received or execution failed")
	}

	fmt.Println("Done!")
}
