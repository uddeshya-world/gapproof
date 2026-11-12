package phonehome

import (
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/uddeshya-world/gapproof/rules"
)

// FuzzLoad feeds fuzzed YAML to the rule loader (M8). Rule packs may come
// from outside the binary (`rules test`), so the loader must reject bad input
// with an error: no panic, no hang (alias bombs), and any rule it accepts
// must satisfy validate().
func FuzzLoad(f *testing.F) {
	names, err := fs.Glob(rules.PhoneHome, "*.yaml")
	if err != nil {
		f.Fatal(err)
	}
	for _, n := range names {
		b, err := fs.ReadFile(rules.PhoneHome, n)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("a: &a [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"))
	f.Add([]byte("id: PH-X\nmatch: {python_package: [a, b]}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		watchdog := time.AfterFunc(10*time.Second, func() {
			panic(fmt.Sprintf("hang: loading a %d-byte rule took longer than 10s", len(data)))
		})
		defer watchdog.Stop()
		rs, err := Load(fstest.MapFS{"PH-FUZZ.yaml": {Data: data}})
		if err != nil {
			return
		}
		for _, r := range rs {
			if r.ID != "PH-FUZZ" {
				t.Fatalf("accepted rule %q from PH-FUZZ.yaml", r.ID)
			}
			if err := r.validate(); err != nil {
				t.Fatalf("accepted an invalid rule: %v", err)
			}
		}
	})
}
