package loader

/*
#include <bfd.h>
#include <stdlib.h>

// The following functions are wrappers so we can use C macros
// that are in bfd in our Go code.

long symtab_upper_bound_bfd(bfd *bfd_h) {
   return bfd_get_symtab_upper_bound(bfd_h);
}

long canonicalize_symtab_bfd(bfd *bfd_h, asymbol **bfd_symtab) {
   return bfd_canonicalize_symtab(bfd_h, bfd_symtab);
}

long dynsym_upper_bound_bfd(bfd *bfd_h) {
   return bfd_get_dynamic_symtab_upper_bound(bfd_h);
}

long canonicalize_dynsym_bfd(bfd *bfd_h, asymbol **bfd_dynsym) {
   return bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// What the symbol represents; currently only functions.
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

// Represents a symbol in an executable file.
type Symbol struct {
	Type SymbolType
	Name string
	Addr uint64
}

func (s Symbol) String() string {
	return fmt.Sprintf("\t%-40s\t%#016x\t%s\t", s.Name, s.Addr, s.Type)
}

func loadSymbols(bfd *C.bfd, bin *Binary) error {
	var n, nsyms C.long
	var bfdSymtab **C.asymbol

	n = C.symtab_upper_bound_bfd(bfd)
	if n < 0 {
		return fmt.Errorf("failed to read symtab: %s", bfdErrmsg())
	}

	if n == 0 {
		// not an error, just no symbols
		return nil
	}

	bfdSymtab = (**C.asymbol)(C.malloc(C.size_t(n)))
	if bfdSymtab == nil {
		return errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(bfdSymtab))

	nsyms = C.canonicalize_symtab_bfd(bfd, bfdSymtab)
	if nsyms < 0 {
		return fmt.Errorf("failed to read symtab: %s", bfdErrmsg())
	}

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

func loadDynsym(bfd *C.bfd, bin *Binary) error {
	var n, nsyms C.long
	var bfdDynsym **C.asymbol

	n = C.dynsym_upper_bound_bfd(bfd)
	if n < 0 {
		return fmt.Errorf("failed to read dynamic symtab: %s", bfdErrmsg())
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
		return fmt.Errorf("failed to read dynamic symtab: %s", bfdErrmsg())
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
