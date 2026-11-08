// Package fsscan safely extracts docker-save / OCI image archives and opens
// unpacked root filesystems for scanning. All content is hostile (CLAUDE.md
// rule 3): nothing is executed, every write is confined to a fresh temp
// directory through os.Root, symlinks are resolved with chroot semantics, and
// every size and count is bounded.
package fsscan

import "fmt"

// Limits bound what an archive can make the extractor do.
type Limits struct {
	MaxEntries      int     // tar entries across all layers
	MaxFileSize     int64   // bytes per regular file
	MaxTotalSize    int64   // bytes written to disk in total
	MaxRatio        float64 // decompressed:compressed bytes, per compressed layer
	RatioFloor      int64   // the ratio is only enforced past this many decompressed bytes
	MaxMetadataSize int64   // manifest.json, index.json, image config, OCI manifest
	MaxOuterMembers int     // members of the outer docker-save tar
}

// DefaultLimits are generous enough for real AI images (multi-GB weights)
// while still stopping bombs. Callers may tighten them.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:      2_000_000,
		MaxFileSize:     256 << 30, // 256 GiB: a single large weight file
		MaxTotalSize:    1 << 40,   // 1 TiB
		MaxRatio:        200,
		RatioFloor:      1 << 30, // 1 GiB
		MaxMetadataSize: 16 << 20,
		MaxOuterMembers: 100_000,
	}
}

// LimitError means a hostile-input limit was hit; the scan is aborted.
type LimitError struct {
	Limit  string
	Detail string
}

func (e *LimitError) Error() string { return fmt.Sprintf("limit exceeded (%s): %s", e.Limit, e.Detail) }

// UnsafePathError means an archive entry tried to leave the extraction root.
type UnsafePathError struct {
	Path   string
	Reason string
}

func (e *UnsafePathError) Error() string {
	return fmt.Sprintf("unsafe path %q rejected: %s", e.Path, e.Reason)
}

// IntegrityError means the archive's content doesn't match its own digests.
type IntegrityError struct {
	What      string
	Want, Got string
}

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("integrity check failed for %s: want %s, got %s", e.What, e.Want, e.Got)
}
