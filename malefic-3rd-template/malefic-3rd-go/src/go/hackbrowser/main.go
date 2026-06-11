package main

/*
#include <stdlib.h>
*/
import "C"
import (
	malefic "malefic-core"
	"unsafe"
)

func init() {
	malefic.RegisterModule(&Module{})
}

//export GoModuleName
func GoModuleName() *C.char {
	return C.CString(malefic.GetModule().Name())
}

//export GoModuleSend
func GoModuleSend(taskId C.uint, data *C.char, dataLen C.int) C.int {
	return C.int(malefic.BridgeSend(uint32(taskId), C.GoBytes(unsafe.Pointer(data), dataLen)))
}

//export GoModuleRecv
func GoModuleRecv(taskId C.uint, outLen *C.int, status *C.int) *C.char {
	out, st := malefic.BridgeRecv(uint32(taskId))
	*status = C.int(st)
	if out == nil {
		return nil
	}
	*outLen = C.int(len(out))
	return (*C.char)(C.CBytes(out))
}

//export GoModuleCloseInput
func GoModuleCloseInput(taskId C.uint) {
	malefic.CloseSessionInput(uint32(taskId))
}

func main() {}
