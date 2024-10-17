package loader

/*
#include <bfd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

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
	"unsafe"
)

type SymbolType int

const (
	SYM_TYPE_UKN SymbolType = iota
	SYM_TYPE_FUNC
)

func (t SymbolType) String() string {
	switch t {
	case SYM_TYPE_FUNC:
		return "FUNC"
	default:
		return "UKN"
	}
}

func (t SymbolType) GoString() string {
	switch t {
	case SYM_TYPE_FUNC:
		return "SYM_TYPE_FUNC"
	default:
		return "SYM_TYPE_UKN"
	}
}

type Symbol struct {
	Type SymbolType
	Name string
	Addr uint64
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
