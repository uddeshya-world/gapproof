package models

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(dir, name string, b []byte) error {
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

func scanDir(t *testing.T, dir string, opt Options) *Result {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	res, err := Scan(context.Background(), root, opt)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
