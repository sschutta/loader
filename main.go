package main

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
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
)

func LoadBinary(fname string, bin *Binary, t BinaryType) error {
	bfd := OpenBfd(fname)
	if bfd == nil {
		return errors.New("could not open binary")
	}
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


	return nil
}

func OpenBfd(fname string) *C.bfd {
	return C.open_bfd(fname)
}

func UnloadBinary(bin *Binary) {
	// TODO figure out if this needs to do anything
}

func init() {
	C.bfd_init()
}

func main() {
	fmt.Println("it compiles")
	fname := os.Args[1]
	bin := new(Binary)
	if err := LoadBinary(fname, bin, BIN_TYPE_AUTO); err != nil {
		fmt.Printf("could not load binary: %v\n", err)
		return
	}
	fmt.Printf("%#v\n", bin)
}
