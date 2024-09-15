package loader

/*
#cgo LDFLAGS: -lbfd

#include <bfd.h>
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

asymbol** get_symtab_bfd(bfd *bfd_h, long *nsyms) {
   long n;
   asymbol **bfd_symtab;

   bfd_symtab = NULL;

   n = bfd_get_symtab_upper_bound(bfd_h);
   if (n < 0) {
       fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
       return NULL;
   } else if (n == 0) {
       fprintf(stderr, "no symbol table\n");
       return NULL;
   }

   bfd_symtab = (asymbol**)malloc(n);
   if (!bfd_symtab) {
       fprintf(stderr, "out of memory\n");
       return NULL;
   }

   *nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
   if (*nsyms < 0) {
       fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
       free(bfd_symtab);
       return NULL;
   }

   return bfd_symtab;
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
		fmt.Printf("error loading symtab: %v", err)
	}
	loadDynsym()

	loadSections()

	return nil
}

func loadSymbols(bfd *C.bfd, bin *Binary) error {
	var nsyms C.long
	bfdSymtab := C.get_symtab_bfd(bfd, &nsyms)
	if bfdSymtab == nil {
		return errors.New("could not process symbol table")
	}
	defer C.free(unsafe.Pointer(bfdSymtab))

	// https://go.dev/wiki/cgo
	symtab := unsafe.Slice(bfdSymtab, nsyms)

	for _, s := range symtab {
		if s.flags & C.BSF_FUNCTION == C.BSF_FUNCTION {
			bin.Symbols = append(bin.Symbols, Symbol{
				Type: SYM_TYPE_FUNC,
				Name: C.GoString(s.name),
				Addr: uint64(C.bfd_asymbol_value(s)),
			})
		}
	}


	return nil
}

func loadDynsym() {}

func loadSections() {}

// Open a binary file using libbfd and return a pointer to a bfd struct.
//
// This function uses our custom C code to implement its workings.
func OpenBfd(fname string) *C.bfd {
	return C.open_bfd(fname)
}

func UnloadBinary(bin *Binary) {
	// TODO figure out if this needs to do anything
}

// Initialize libbfd when the program starts.
func init() {
	C.bfd_init()
}
