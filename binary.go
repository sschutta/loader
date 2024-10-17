package loader

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
