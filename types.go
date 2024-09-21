package loader

import "unsafe"

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

func (b *Binary) GetTextSection() *Section {
	for _, s := range b.Sections {
		if s.Name == ".text" {
			return &s
		}
	}
	return nil
}
