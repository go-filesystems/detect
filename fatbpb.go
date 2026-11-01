package detect

import (
	"io"
	"math/bits"
)

// FAT12 and FAT16 have no filesystem-type magic worth the name: the
// "FAT12   "/"FAT16   " label at 0x36 is informational only (Microsoft's FAT
// specification, fatgen103, says so, and mkfs tools leave it blank or wrong),
// and the boot sector of a FAT volume shares its 0xAA55 signature with every
// MBR. The only sound test is the one the specification gives for telling the
// variants apart, which is also a strong test that the sector is a FAT boot
// sector at all: decode the BIOS parameter block, compute the count of data
// clusters, and require every field to be consistent with it.
//
//	RootDirSectors  = (RootEntCnt*32 + BytsPerSec-1) / BytsPerSec
//	FirstDataSector = RsvdSecCnt + NumFATs*FATSz16 + RootDirSectors
//	CountOfClusters = (TotSec - FirstDataSector) / SecPerClus
//
// A count below 4085 is FAT12, below 65525 FAT16. A FAT12/16 layout (non-zero
// BPB_FATSz16) claiming more clusters is not a FAT12/16 volume and is not
// reported as one. The FAT32 layout (BPB_FATSz16 == 0) is the "FAT32   " probe's.
//
// Sources, opened 2026-11-01: fatgen103 "FAT Type Determination"; Linux
// fs/fat/inode.c fat_fill_super (same count, same thresholds).

// fatBPBLen covers every field read: up to the end of the FAT12/16 extended
// boot record's type label (offset 62).
const fatBPBLen = 64

const (
	maxFAT12Clusters = 4084
	maxFAT16Clusters = 65524
)

// fatBPBType reports FAT12 or FAT16 when the first sector of r is a
// self-consistent FAT12/16 boot sector, and Unknown otherwise. size may be
// negative (unknown); when known, the fixed regions the BPB describes must fit
// in it. Every arithmetic step is in uint64: a forged field cannot wrap.
func fatBPBType(r io.ReaderAt, size int64) Type {
	b, ok := readAt(r, size, 0, fatBPBLen)
	if !ok {
		return Unknown
	}
	if sig, ok := readAt(r, size, 510, 2); !ok || le.Uint16(sig) != bootSig {
		return Unknown
	}
	// BS_jmpBoot: 0xEB ?? 0x90 or 0xE9 ?? ??; only the opcode is checked, as
	// mkfs tools differ on the rest.
	if b[0] != 0xEB && b[0] != 0xE9 {
		return Unknown
	}
	bps := uint64(le.Uint16(b[11:]))
	spc := uint64(b[13])
	rsvd := uint64(le.Uint16(b[14:]))
	nfats := uint64(b[16])
	rootEnt := uint64(le.Uint16(b[17:]))
	media := b[21]
	fatSz := uint64(le.Uint16(b[22:]))
	total := uint64(le.Uint16(b[19:]))
	if total == 0 {
		total = uint64(le.Uint32(b[32:]))
	}
	switch bps {
	case 512, 1024, 2048, 4096:
	default:
		return Unknown
	}
	if spc == 0 || bits.OnesCount64(spc) != 1 || rsvd == 0 || nfats == 0 || fatSz == 0 || total == 0 {
		return Unknown
	}
	// BPB_Media: 0xF0 or 0xF8..0xFF.
	if media != 0xF0 && media < 0xF8 {
		return Unknown
	}
	rootBytes := rootEnt * 32
	if rootEnt == 0 || rootBytes%bps != 0 {
		return Unknown
	}
	dataStart := rsvd + nfats*fatSz + rootBytes/bps
	if dataStart >= total {
		return Unknown
	}
	if size >= 0 && dataStart*bps > uint64(size) {
		return Unknown
	}
	count := (total - dataStart) / spc
	switch {
	case count == 0 || count > maxFAT16Clusters:
		return Unknown
	case count <= maxFAT12Clusters:
		return FAT12
	}
	return FAT16
}
