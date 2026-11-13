package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Limits for headers we accept before handing a file to debug/elf and
// debug/buildinfo. Those parsers size their reads from header fields, so a
// 64-byte file can make them allocate tens of megabytes (found by FuzzScanELF).
// Rule 3: scanned content is hostile, so every size and offset is checked against
// the real file size first.
const (
	maxELFSections = 1 << 16 // sections we accept (the 16-bit e_shnum range)
	elfSHTNobits   = 8
)

var errELF = errors.New("malformed ELF")

func elfErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errELF, fmt.Sprintf(format, a...))
}

// validateELF checks the ELF header, the program header table, the section
// header table and every file-backed section (which covers the string tables)
// against size, the file's real length. It reads at most 16 bytes past the
// header plus the section header table, which has to fit inside the file.
func validateELF(r io.ReaderAt, size int64) error {
	var h [64]byte
	n, _ := r.ReadAt(h[:], 0)
	if n < 16 || string(h[:4]) != "\x7fELF" {
		return elfErr("no ELF header")
	}
	var bo binary.ByteOrder
	switch h[5] {
	case 1:
		bo = binary.LittleEndian
	case 2:
		bo = binary.BigEndian
	default:
		return elfErr("unknown byte order %d", h[5])
	}
	var (
		is64                      bool
		hdrLen                    int
		phoff, shoff              uint64
		phentsize, phnum          uint64
		shentsize, shnum, shstrnd uint64
		minPh, minSh              uint64
	)
	switch h[4] {
	case 1:
		hdrLen, minPh, minSh = 52, 32, 40
	case 2:
		is64, hdrLen, minPh, minSh = true, 64, 56, 64
	default:
		return elfErr("unknown class %d", h[4])
	}
	if n < hdrLen {
		return elfErr("truncated header (%d bytes)", n)
	}
	if is64 {
		phoff, shoff = bo.Uint64(h[32:]), bo.Uint64(h[40:])
		phentsize, phnum = uint64(bo.Uint16(h[54:])), uint64(bo.Uint16(h[56:]))
		shentsize, shnum, shstrnd = uint64(bo.Uint16(h[58:])), uint64(bo.Uint16(h[60:])), uint64(bo.Uint16(h[62:]))
	} else {
		phoff, shoff = uint64(bo.Uint32(h[28:])), uint64(bo.Uint32(h[32:]))
		phentsize, phnum = uint64(bo.Uint16(h[42:])), uint64(bo.Uint16(h[44:]))
		shentsize, shnum, shstrnd = uint64(bo.Uint16(h[46:])), uint64(bo.Uint16(h[48:])), uint64(bo.Uint16(h[50:]))
	}
	usize := uint64(size)

	if phnum > 0 {
		if phentsize < minPh {
			return elfErr("program header entry size %d < %d", phentsize, minPh)
		}
		if !fits(phoff, phnum*phentsize, usize) {
			return elfErr("program header table (%d x %d at %d) exceeds the %d-byte file", phnum, phentsize, phoff, size)
		}
	}
	if shoff == 0 {
		return nil // no section table: debug/elf reads none
	}
	if shentsize < minSh {
		return elfErr("section header entry size %d < %d", shentsize, minSh)
	}
	if !fits(shoff, shentsize, usize) {
		return elfErr("section header table at %d exceeds the %d-byte file", shoff, size)
	}
	sh0 := make([]byte, shentsize)
	if _, err := r.ReadAt(sh0, int64(shoff)); err != nil {
		return elfErr("section 0 unreadable: %v", err)
	}
	// Extended numbering: the real count and string-table index live in section 0.
	if shnum == 0 {
		if is64 {
			shnum = bo.Uint64(sh0[32:])
		} else {
			shnum = uint64(bo.Uint32(sh0[20:]))
		}
	}
	if shstrnd == 0xffff {
		if is64 {
			shstrnd = uint64(bo.Uint32(sh0[40:]))
		} else {
			shstrnd = uint64(bo.Uint32(sh0[24:]))
		}
	}
	if shnum == 0 {
		return nil
	}
	if shnum > maxELFSections {
		return elfErr("%d sections (limit %d)", shnum, maxELFSections)
	}
	if !fits(shoff, shnum*shentsize, usize) {
		return elfErr("section header table (%d x %d at %d) exceeds the %d-byte file", shnum, shentsize, shoff, size)
	}
	if shstrnd >= shnum {
		return elfErr("section name table index %d >= %d sections", shstrnd, shnum)
	}
	tab := make([]byte, shnum*shentsize) // at most 4 MiB, and inside the file
	if _, err := r.ReadAt(tab, int64(shoff)); err != nil {
		return elfErr("section header table unreadable: %v", err)
	}
	for i := uint64(0); i < shnum; i++ {
		sh := tab[i*shentsize:]
		var typ uint32
		var off, sz uint64
		typ = bo.Uint32(sh[4:])
		if is64 {
			off, sz = bo.Uint64(sh[24:]), bo.Uint64(sh[32:])
		} else {
			off, sz = uint64(bo.Uint32(sh[16:])), uint64(bo.Uint32(sh[20:]))
		}
		if typ == elfSHTNobits {
			continue
		}
		if !fits(off, sz, usize) {
			return elfErr("section %d (%d bytes at %d) exceeds the %d-byte file", i, sz, off, size)
		}
	}
	return nil
}

// fits reports whether [off, off+n) lies inside a file of the given size,
// without overflowing.
func fits(off, n, size uint64) bool {
	return off <= size && n <= size-off
}
