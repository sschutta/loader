package loader

import (
	"unsafe"
)

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

type Section struct {
	Binary   *Binary
	Name     string
	Type     SectionType
	Vma      uint64
	Size     uint64
	Bytes    []uint8
	BytesPtr unsafe.Pointer
}

func (s *Section) Contains(addr uint64) bool {
	return (addr >= s.Vma) && (addr-s.Vma < s.Size)
}
