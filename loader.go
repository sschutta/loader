package loader

/*
#cgo LDFLAGS: -lbfd

#include <bfd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

bfd* open_bfd(_GoString_ fname) {
   bfd *bfd_h;
   bfd_h = bfd_openr(_GoStringPtr(fname), NULL);
   if(!bfd_h) {
       fprintf(stderr, "failed to open binary '%s' (%s)\n", _GoStringPtr(fname), bfd_errmsg(bfd_get_error()));
       return NULL;
   }
   if(!bfd_check_format(bfd_h, bfd_object)) {
       fprintf(stderr, "file '%s' does not look like an executable (%s)\n", _GoStringPtr(fname), bfd_errmsg(bfd_get_error()));
       return NULL;
   }
   bfd_set_error(bfd_error_no_error);
   if(bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
       fprintf(stderr, "unrecognized format for binary '%s' (%s)\n", _GoStringPtr(fname), bfd_errmsg(bfd_get_error()));
       return NULL;
   }
   return bfd_h;
}

long dynsym_upper_bound_bfd(bfd *bfd_h) {
   return bfd_get_symtab_upper_bound(bfd_h);
}

long canonicalize_dynsym_bfd(bfd *bfd_h, asymbol **bfd_dynsym) {
   return bfd_canonicalize_symtab(bfd_h, bfd_dynsym);
}

flagword get_section_flags_bfd(asection *bfd_sec) {
   return bfd_sec->flags;
}

*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Load the data from a binary file into our Binary type
//
// Practical Binary Analysis, Ch.4, p.75
func LoadBinary(fname string, bin *Binary, t BinaryType) error {
	bfd := OpenBfd(fname)
	if bfd == nil {
		return errors.New("could not open binary")
	}
	// bfd_close handles freeing the pointer
	defer C.bfd_close(bfd)

	bin.Filename = fname
	bin.Entry = uint64(C.bfd_get_start_address(bfd))
	bin.TypeStr = C.GoString(bfd.xvec.name)

	switch bfd.xvec.flavour {
	case C.bfd_target_elf_flavour:
		bin.Type = BIN_TYPE_ELF
	case C.bfd_target_coff_flavour:
		bin.Type = BIN_TYPE_PE
	case C.bfd_target_unknown_flavour:
	default:
		fmt.Printf("unsupported binary type (%s)\n", bin.TypeStr)
		return errors.New("unsupported binary type")
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
		fmt.Printf("unsupported architecture (%s)\n", bin.ArchStr)
		return errors.New("unsupported architecture")
	}

	if err := loadSymbols(bfd, bin); err != nil {
		fmt.Printf("error loading symtab: %v\n", err)
	}

	if err := loadDynsym(bfd, bin); err != nil {
		fmt.Printf("error loading dynsym: %v\n", err)
	}

	if err := loadSections(bfd, bin); err != nil {
		fmt.Printf("error loading sections: %v\n", err)
	}

	return nil
}

func loadDynsym(bfd *C.bfd, bin *Binary) error {
	var n, nsyms C.long
	var bfdDynsym **C.asymbol

	n = C.dynsym_upper_bound_bfd(bfd)
	if n < 0 {
		errmsg := C.GoString(C.bfd_errmsg(C.bfd_get_error()))
		return fmt.Errorf("failed to read dynamic symtab (%s)", errmsg)
	}

	if n == 0 {
		// not an error, just no symbols
		return nil
	}

	bfdDynsym = (**C.asymbol)(C.malloc(C.size_t(n)))
	if bfdDynsym == nil {
		return errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(bfdDynsym))

	nsyms = C.canonicalize_dynsym_bfd(bfd, bfdDynsym)
	if nsyms < 0 {
		errmsg := C.GoString(C.bfd_errmsg(C.bfd_get_error()))
		return fmt.Errorf("failed to read dynamic symtab (%s)", errmsg)
	}

	dynsym := unsafe.Slice(bfdDynsym, nsyms)

	for _, s := range dynsym {
		if s.flags&C.BSF_FUNCTION == C.BSF_FUNCTION {
			bin.Symbols = append(bin.Symbols, Symbol{
				Type: SYM_TYPE_FUNC,
				Name: C.GoString(s.name),
				Addr: uint64(C.bfd_asymbol_value(s)),
			})
		}
	}

	return nil
}

func loadSections(bfd *C.bfd, bin *Binary) error {
	for bfdSec := bfd.sections; bfdSec != nil; bfdSec = bfdSec.next {
		bfdFlags := C.get_section_flags_bfd(bfdSec)
		secType := SEC_TYPE_NONE
		switch {
		case bfdFlags&C.SEC_CODE == C.SEC_CODE:
			secType = SEC_TYPE_CODE
		case bfdFlags&C.SEC_DATA == C.SEC_DATA:
			secType = SEC_TYPE_DATA
		default:
			continue
		}

		vma := C.bfd_section_vma(bfdSec)
		size := C.bfd_section_size(bfdSec)
		secname := C.bfd_section_name(bfdSec)
		secName := C.GoString(secname)

		if secName == "" {
			secName = "<unnamed>"
		}

		var bytes = C.malloc(size)

		if success := C.bfd_get_section_contents(bfd, bfdSec, bytes, 0, size); success == C.false {
			errmsg := C.GoString(C.bfd_errmsg(C.bfd_get_error()))
			return fmt.Errorf("could not get section contents: %v", errmsg)
		}

		bin.Sections = append(bin.Sections, Section{
			Binary:   bin,
			Name:     secName,
			Type:     secType,
			Vma:      uint64(vma),
			Size:     uint64(size),
			Bytes:    C.GoBytes(bytes, C.int(size)),
			BytesPtr: bytes,
		})
	}

	return nil
}

// Open a binary file using libbfd and return a pointer to a bfd struct.
//
// This function uses our custom C code to implement its workings.
func OpenBfd(fname string) *C.bfd {
	return C.open_bfd(fname)
}

func UnloadBinary(bin *Binary) {
	for _, sec := range bin.Sections {
		C.free(sec.BytesPtr)
	}
}

// Initialize libbfd when the program starts.
func init() {
	C.bfd_init()
}
