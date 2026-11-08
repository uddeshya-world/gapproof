package phonehome

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/inventory"
)

// A fixture directory, used by `gapproof rules test` and the rule tests:
//
//	<dir>/rootfs/   the filesystem to scan
//	<dir>/env.txt   optional image environment, one KEY=VALUE per line
//	                (blank lines and # comments ignored)
//
// It holds hand-written test content and is read like any scanned image.

// LoadFixture builds an Input from a fixture directory. Call close when done.
func LoadFixture(ctx context.Context, dir string) (in Input, close func(), err error) {
	rootDir := filepath.Join(dir, "rootfs")
	if fi, err := os.Stat(rootDir); err != nil || !fi.IsDir() {
		return Input{}, nil, errors.New(dir + ": a fixture needs a rootfs/ directory")
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return Input{}, nil, err
	}
	inv, err := inventory.Build(ctx, root, inventory.DefaultLimits())
	if err != nil {
		root.Close()
		return Input{}, nil, err
	}
	env, err := readEnvFile(filepath.Join(dir, "env.txt"))
	if err != nil {
		root.Close()
		return Input{}, nil, err
	}
	return Input{Root: root, Inv: inv, Env: env, ConfigDigest: "sha256:fixture"}, func() { root.Close() }, nil
}

func readEnvFile(p string) ([]string, error) {
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var env []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		env = append(env, l)
	}
	return env, sc.Err()
}

// ByID returns the rule with that id.
func ByID(rs []*Rule, id string) *Rule {
	for _, r := range rs {
		if r.ID == id {
			return r
		}
	}
	return nil
}
