package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/fsscan"
)

// Pinned harness image identity, set at release with -ldflags -X (see the
// Makefile `harness` target). The harness image contains a gapproof binary
// built without these values, which avoids the binary-in-image circularity.
// Layers are the comma-separated diff_ids: content addresses that are the
// same in every engine and storage backend (the engine "image ID" is not:
// D-011). Empty values mean an unpinned development build.
var (
	PinnedConfigDigest string
	PinnedLayers       string
)

// ImageRepo is the local repository name of the harness image.
const ImageRepo = "gapproof-harness"

// ImageRef is the tag the harness image is loaded under.
func ImageRef() string {
	if PinnedConfigDigest == "" {
		return ImageRepo + ":dev"
	}
	return ImageRepo + ":" + strings.TrimPrefix(PinnedConfigDigest, "sha256:")[:12]
}

// ErrHarnessMissing means the harness image isn't loaded. Never pull it.
var ErrHarnessMissing = errors.New("the harness image " + ImageRef() + " is not loaded; run `gapproof harness load gapproof-harness-<version>.oci.tar` (shipped with each release; it is never pulled)")

// Pinned reports whether this binary pins a harness image.
func Pinned() bool { return PinnedConfigDigest != "" }

// Digest returns the verified config digest and layer diff_ids of an image
// tarball: the values a release pins.
func Digest(ctx context.Context, tarPath string) (string, []string, error) {
	im, err := fsscan.ExtractImage(ctx, tarPath, fsscan.DefaultLimits())
	if err != nil {
		return "", nil, err
	}
	defer im.Close()
	return im.ConfigDigest, diffIDs(im), nil
}

// Load verifies an image tarball (integrity chain and, for pinned builds,
// the pinned config digest and layers) before loading and tagging it.
func Load(ctx context.Context, e *Engine, tarPath string) (string, error) {
	cfg, layers, err := Digest(ctx, tarPath)
	if err != nil {
		return "", fmt.Errorf("harness image %s: %w", tarPath, err)
	}
	if Pinned() {
		if cfg != PinnedConfigDigest || !slices.Equal(layers, pinnedLayers()) {
			return "", fmt.Errorf("harness image %s has config %s; this gapproof build pins %s (use the tarball from the same release)", tarPath, cfg, PinnedConfigDigest)
		}
	}
	out, err := e.run(ctx, "load", "-i", tarPath)
	if err != nil {
		return "", err
	}
	src := loadedRef(string(out))
	if src == "" {
		return "", fmt.Errorf("couldn't find the loaded image in: %s", strings.TrimSpace(string(out)))
	}
	if _, err := e.run(ctx, "tag", src, ImageRef()); err != nil {
		return "", err
	}
	if err := Check(ctx, e); err != nil {
		return "", err
	}
	return cfg, nil
}

func diffIDs(im *fsscan.Image) []string {
	var l []string
	for _, x := range im.Layers {
		l = append(l, x.DiffID)
	}
	return l
}

func pinnedLayers() []string {
	if PinnedLayers == "" {
		return nil
	}
	return strings.Split(PinnedLayers, ",")
}

var loadedRe = regexp.MustCompile(`(?m)^Loaded image(?: ID)?: (\S+)\s*$`)

func loadedRef(out string) string {
	m := loadedRe.FindAllStringSubmatch(out, -1)
	if len(m) == 0 {
		return ""
	}
	return m[len(m)-1][1]
}

// Check confirms the harness image is present and (pinned builds) that its
// layers are exactly the pinned ones. It never pulls.
func Check(ctx context.Context, e *Engine) error {
	out, err := e.run(ctx, "image", "inspect", "--format", "{{json .RootFS.Layers}}", ImageRef())
	if err != nil {
		return ErrHarnessMissing
	}
	if !Pinned() {
		return nil
	}
	var layers []string
	if err := json.Unmarshal(out, &layers); err != nil {
		return fmt.Errorf("inspect harness image: %w", err)
	}
	if !slices.Equal(layers, pinnedLayers()) {
		return fmt.Errorf("local %s does not match the pinned harness layers; reload it with `gapproof harness load`", ImageRef())
	}
	return nil
}

// TargetInfo is what the harness needs from the target image's config.
type TargetInfo struct {
	ExposedPorts []string          // e.g. "8000/tcp", sorted
	Labels       map[string]string // for the capability check
	User         string
}

// InspectTarget reads the target image config (it must exist locally; it is
// never pulled).
func InspectTarget(ctx context.Context, e *Engine, ref string) (TargetInfo, error) {
	out, err := e.run(ctx, "image", "inspect", "--format", "{{json .Config}}", ref)
	if err != nil {
		return TargetInfo{}, fmt.Errorf("target image %s is not available locally (it is never pulled): %w", ref, err)
	}
	var c struct {
		ExposedPorts map[string]struct{}
		Labels       map[string]string
		User         string
	}
	if err := json.Unmarshal(out, &c); err != nil {
		return TargetInfo{}, err
	}
	ti := TargetInfo{Labels: c.Labels, User: c.User}
	for p := range c.ExposedPorts {
		ti.ExposedPorts = append(ti.ExposedPorts, p)
	}
	slices.Sort(ti.ExposedPorts)
	return ti, nil
}

var capRe = regexp.MustCompile(`(?i)\b(?:cap_)?net_(?:admin|raw)\b`)

// RequestedNetCaps returns the label entries asking for NET_ADMIN/NET_RAW.
// An image can't grant itself capabilities, but one that documents needing
// them (labels such as "capabilities", compose-style "cap_add", or app
// manifests) would expect to rewrite the netns rules, so the harness refuses
// it instead of silently running it degraded.
func RequestedNetCaps(labels map[string]string) []string {
	var hits []string
	for k, v := range labels {
		if capRe.MatchString(k) || capRe.MatchString(v) {
			hits = append(hits, k+"="+v)
		}
	}
	slices.Sort(hits)
	return hits
}
