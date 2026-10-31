package nlt

import (
	"syscall"
	"unsafe"
)

var procWideCharToMultiByte = syscall.NewLazyDLL("kernel32.dll").NewProc("WideCharToMultiByte")

const cpThreadACP = 3

// wideToACP calls WideCharToMultiByte(CP_THREAD_ACP, 0, ...) like CStringA's conversion (0x402860).
func wideToACP(u []uint16) []byte {
	if len(u) == 0 {
		return nil
	}
	n, _, _ := procWideCharToMultiByte.Call(cpThreadACP, 0, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)), 0, 0, 0, 0)
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	procWideCharToMultiByte.Call(cpThreadACP, 0, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)),
		uintptr(unsafe.Pointer(&out[0])), n, 0, 0)
	return out
}
