//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleCP     = kernel32.NewProc("SetConsoleCP")
	procSetConsoleOutCP  = kernel32.NewProc("SetConsoleOutputCP")
	procGetConsoleMode   = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode   = kernel32.NewProc("SetConsoleMode")
	procGetStdHandle     = kernel32.NewProc("GetStdHandle")
)

const (
	CP_UTF8                            = 65001
	STD_OUTPUT_HANDLE                  = ^uintptr(10) // -11
	ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
)

func init() {
	// Force console to UTF-8 code page for input and output.
	// This enables proper rendering of international characters
	// (Arabic, CJK, Cyrillic, Devanagari, etc.) in Windows terminals.
	procSetConsoleCP.Call(CP_UTF8)
	procSetConsoleOutCP.Call(CP_UTF8)

	// Enable virtual terminal processing (ANSI escape sequences).
	// Modern Windows Terminal supports this natively, but older
	// cmd.exe/PowerShell need it enabled explicitly.
	handle, _, _ := procGetStdHandle.Call(STD_OUTPUT_HANDLE)
	if handle != 0 && handle != uintptr(syscall.InvalidHandle) {
		var mode uint32
		procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
		procSetConsoleMode.Call(handle, uintptr(mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING))
	}

	// Also set Go's stdout to binary mode to prevent line-ending mangling.
	os.Stdout.Fd()
}
