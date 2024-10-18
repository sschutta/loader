package loader

/*
#include <bfd.h>
#include <stdbool.h>

// Convenience function to get the section flags in Go.
flagword get_section_flags_bfd(asection *bfd_sec) {
   return bfd_sec->flags;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Whether the section holds code or data.
type SectionType int

const (
	SEC_TYPE_NONE SectionType = iota
	SEC_TYPE_CODE
	SEC_TYPE_DATA
)

func (t SectionType) String() string {
	switch t {
	case SEC_TYPE_CODE:
		return "CODE"
	case SEC_TYPE_DATA:
		return "DATA"
	default:
		return "NONE"
	}
}

func (t SectionType) GoString() string {
	switch t {
	case SEC_TYPE_CODE:
		return "SEC_TYPE_CODE"
	case SEC_TYPE_DATA:
		return "SEC_TYPE_DATA"
	default:
		return "SEC_TYPE_NONE"
	}
}

// Represents a section of an executable file.
type Section struct {
	Binary   *Binary
	Name     string
	Type     SectionType
	Vma      uint64
	Size     uint64
	Bytes    []uint8
	BytesPtr unsafe.Pointer
}

func (s Section) String() string {
	return fmt.Sprintf("\t%#016x\t%-8d\t%-20s\t%s\t", s.Vma, s.Size, s.Name, s.Type)
}

// Returns true if the address is in this section.
func (s *Section) Contains(addr uint64) bool {
	return (addr >= s.Vma) && (addr-s.Vma < s.Size)
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
			return fmt.Errorf("could not get section contents: %v", bfdErrmsg())
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
