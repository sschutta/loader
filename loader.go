package loader

/*
#cgo LDFLAGS: -lbfd

#include <bfd.h>
#include <stdbool.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// The format of the binary; currently just ELF and PE.
type BinaryType int

const (
	BIN_TYPE_AUTO BinaryType = iota
	BIN_TYPE_ELF
	BIN_TYPE_PE
)

func (t BinaryType) String() string {
	switch t {
	case BIN_TYPE_ELF:
		return "ELF"
	case BIN_TYPE_PE:
		return "PE"
	default:
		return "AUTO"
	}
}

func (t BinaryType) GoString() string {
	switch t {
	case BIN_TYPE_ELF:
		return "BIN_TYPE_ELF"
	case BIN_TYPE_PE:
		return "BIN_TYPE_PE"
	default:
		return "BIN_TYPE_AUTO"
	}
}

// The architecture of the binary; currently only x86.
type BinaryArch int

const (
	ARCH_NONE BinaryArch = iota
	ARCH_X86
)

func (t BinaryArch) String() string {
	switch t {
	case ARCH_X86:
		return "x86"
	default:
		return "NONE"
	}
}

func (t BinaryArch) GoString() string {
	switch t {
	case ARCH_X86:
		return "ARCH_X86"
	default:
		return "ARCH_NONE"
	}
}

// Represents an executable binary file.
type Binary struct {
	Filename string
	Type     BinaryType
	TypeStr  string
	Arch     BinaryArch
	ArchStr  string
	Bits     uint
	Entry    uint64
	Sections []Section
	Symbols  []Symbol
}

func (b *Binary) String() string {
	return fmt.Sprintf("%q %s/%s (%d bits) entry@%#016x", b.Filename, b.TypeStr, b.ArchStr, b.Bits, b.Entry)
}

// Get the .text section for this binary.
func (b *Binary) GetTextSection() *Section {
	for _, s := range b.Sections {
		if s.Name == ".text" {
			return &s
		}
	}
	return nil
}

// Free the pointers to the section bytes.
func (b *Binary) Free() {
	for _, s := range b.Sections {
		C.free(s.BytesPtr)
	}
}

// Load the data from a binary file into our Binary type.
//
// Practical Binary Analysis, Ch.4, p.75
func LoadBinary(fname string, bin *Binary, t BinaryType) error {
	bfd, err := openBfd(fname)
	defer func() {
		if bfd != nil {
			// bfd_close handles freeing the pointer
			C.bfd_close(bfd)
		}
	}()

	if err != nil {
		return err
	}

	bin.Filename = fname
	bin.Entry = uint64(C.bfd_get_start_address(bfd))
	bin.TypeStr = C.GoString(bfd.xvec.name)

	switch bfd.xvec.flavour {
	case C.bfd_target_elf_flavour:
		bin.Type = BIN_TYPE_ELF
	case C.bfd_target_coff_flavour:
		bin.Type = BIN_TYPE_PE
	case C.bfd_target_unknown_flavour:
		fallthrough
	default:
		return fmt.Errorf("unsupported binary type %q", bin.TypeStr)
	}

	bfdInfo := C.bfd_get_arch_info(bfd)
	bin.ArchStr = C.GoString(bfdInfo.printable_name)

	switch bfdInfo.mach {
	case C.bfd_mach_i386_i386:
		bin.Arch = ARCH_X86
		bin.Bits = 32
	case C.bfd_mach_x86_64:
		bin.Arch = ARCH_X86
		bin.Bits = 64
	default:
		return fmt.Errorf("unsupported architecture %q", bin.ArchStr)
	}

	if err := loadSymbols(bfd, bin); err != nil {
		fmt.Printf("error loading symtab: %v\n", err)
	}

	if err := loadDynsym(bfd, bin); err != nil {
		fmt.Printf("error loading dynsym: %v\n", err)
	}

	if err := loadSections(bfd, bin); err != nil {
		return fmt.Errorf("error loading sections: %v", err)
	}

	return nil
}

// Open a binary file using libbfd and return a pointer to a bfd struct.
func openBfd(fname string) (*C.bfd, error) {
	cfname := C.CString(fname)
	defer C.free(unsafe.Pointer(cfname))

	bfdH := C.bfd_openr(cfname, nil)
	if bfdH == nil {
		return nil, fmt.Errorf("failed to open binary %q: %s", fname, bfdErrmsg())
	}

	if C.bfd_check_format(bfdH, C.bfd_object) == C.false {
		return bfdH, fmt.Errorf("file %q does not look like an executable: %s", fname, bfdErrmsg())
	}

	C.bfd_set_error(C.bfd_error_no_error)

	if C.bfd_get_flavour(bfdH) == C.bfd_target_unknown_flavour {
		return bfdH, fmt.Errorf("unrecognized format for binary %q: %s", fname, bfdErrmsg())
	}

	return bfdH, nil
}

// Unload a Binary, freeing any held C pointers.
func UnloadBinary(bin *Binary) {
	bin.Free()
}

// Helper to get the bfd error message.
func bfdErrmsg() string {
	return C.GoString(C.bfd_errmsg(C.bfd_get_error()))
}

// Initialize libbfd when the program starts.
func init() {
	C.bfd_init()
}
