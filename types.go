package main

type SymbolType int

const (
	SYM_TYPE_UKN SymbolType = iota
	SYM_TYPE_FUNC
)

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

type Section struct {
	Binary *Binary
	Name   string
	Type   SectionType
	Vma    uint64
	Size   uint64
	Bytes  []uint8
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

type BinaryArch int

const (
	ARCH_NONE BinaryArch = iota
	ARCH_X86
)

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
