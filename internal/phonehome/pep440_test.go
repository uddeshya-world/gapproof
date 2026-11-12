package phonehome

import (
	"strings"
	"testing"
	"testing/fstest"
)

// TestVersionBoundEvaluate: out-of-range versions don't match, and a
// version that isn't PEP 440 matches with a note (fail closed).
func TestVersionBoundEvaluate(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	r := ByID(rs, "PH-CHROMA-TELEMETRY")
	for version, want := range map[string]string{
		"1.5.2":        "in affected range <1.5.4",
		"1.5.4rc1":     "in affected range <1.5.4",
		"1.5.4":        "",
		"1.6.0":        "",
		"1.5.2-local!": "version isn't PEP 440 so treated as in affected range <1.5.4",
	} {
		dir := t.TempDir()
		writeFixture(t, dir, fixture{nil, withDist("chromadb", version)})
		got := strings.ReplaceAll(string(evalFixture(t, r, dir)), "\\u003c", "<")
		switch {
		case want == "" && got != "[]\n":
			t.Errorf("chromadb %s matched:\n%s", version, got)
		case want != "" && !strings.Contains(got, want):
			t.Errorf("chromadb %s: want detail containing %q, got\n%s", version, want, got)
		}
	}
}

// pep440Order is strictly increasing in PEP 440's total order; the
// sequence follows packaging's own test suite (VERSIONS in test_version.py).
var pep440Order = []string{
	"1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12",
	"1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456", "1.0b2.post345",
	"1.0rc1.dev456", "1.0rc1", "1.0", "1.0+abc.5", "1.0+abc.7", "1.0+5", "1.0.post456.dev34",
	"1.0.post456", "1.0.15", "1.1.dev1",
	"1.5.3", "1.5.4.dev0", "1.5.4a1", "1.5.4rc1", "1.5.4", "1.5.4+local", "1.5.4.post1", "1.5.10",
	"1!0.1",
}

func TestVersionTotalOrder(t *testing.T) {
	vs := make([]pepVersion, len(pep440Order))
	for i, s := range pep440Order {
		v, err := parseVersion(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		vs[i] = v
	}
	for i := range vs {
		for j := range vs {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := compareVersions(vs[i], vs[j]); got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", pep440Order[i], pep440Order[j], got, want)
			}
		}
	}
}

func TestVersionNormalisation(t *testing.T) {
	for in, want := range map[string]string{
		"1.0":                       "1",
		"1.0.0":                     "1",
		"v1.5.4":                    "1.5.4",
		" 1.5.4 ":                   "1.5.4",
		"1.0-1":                     "1.post1",
		"1.0.post":                  "1.post0",
		"1.0rev2":                   "1.post2",
		"1.0-r3":                    "1.post3",
		"1.0alpha1":                 "1a1",
		"1.0-beta.2":                "1b2",
		"1.0c1":                     "1rc1",
		"1.0preview3":               "1rc3",
		"1.0RC1":                    "1rc1",
		"1.0.dev":                   "1.dev0",
		"1.0-dev-7":                 "1.dev7",
		"0!1.0":                     "1",
		"2!1.0":                     "2!1",
		"1.0+Ubuntu-1_A":            "1+ubuntu.1.a",
		"00001.002":                 "1.2",
		"99999999999999999999999.1": "99999999999999999999999.1",
	} {
		v, err := parseVersion(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := v.String(); got != want {
			t.Errorf("%q normalises to %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "1.", ".1", "1..2", "1.0+", "1.0+a..b", "1.0-", "1 0", "1.0 rc1 x", "=1", strings.Repeat("1.", 200) + "1"} {
		if _, err := parseVersion(bad); err == nil {
			t.Errorf("%q parsed, want an error", bad)
		}
	}
}

func TestVersionSpec(t *testing.T) {
	tests := []struct {
		spec    string
		version string
		in, ok  bool
	}{
		{"<1.5.4", "1.5.2", true, true},
		{"<1.5.4", "0.5.23", true, true},
		{"<1.5.4", "1.5.4", false, true},
		{"<1.5.4", "1.5.4.0", false, true},
		{"<1.5.4", "1.5.10", false, true},
		{"<1.5.4", "2.0.0", false, true},
		{"<1.5.4", "1.5.4rc1", true, true}, // total order: a pre-release of the fix may not have it
		{"<1.5.4", "1.5.4.dev3", true, true},
		{"<1.5.4", "1.5.4.post1", false, true},
		{"<1.5.4", "1!0.1", false, true},
		{"<1.5.4", "not-a-version", true, false}, // fail closed
		{"<1.5.4", "", true, false},
		{">=0.4, <1.5.4", "0.3.29", false, true},
		{">=0.4,<1.5.4", "0.4.0", true, true},
		{"<=1.0", "1.0.0", true, true},
		{">1.0", "1.0.post1", true, true},
		{"==1.0", "1", true, true},
		{"!=1.0", "1.0.0", false, true},
		{"!=1.0", "1.0.1", true, true},
	}
	for _, tc := range tests {
		s, err := parseSpec(tc.spec)
		if err != nil {
			t.Fatalf("%s: %v", tc.spec, err)
		}
		in, ok := s.Contains(tc.version)
		if in != tc.in || ok != tc.ok {
			t.Errorf("%q contains %q = (%v, %v), want (%v, %v)", tc.spec, tc.version, in, ok, tc.in, tc.ok)
		}
	}
	for _, bad := range []string{"", " ", "1.5.4", "~=1.5", "===1.5", "==1.5.*", "<", "<abc", "<1.5,", "=>1.5", strings.Repeat("<1,", 20) + "<1"} {
		if _, err := parseSpec(bad); err == nil {
			t.Errorf("spec %q parsed, want an error", bad)
		}
	}
	if s, _ := parseSpec(" >= 0.4.0 , < 1.5.4 "); s.String() != ">=0.4,<1.5.4" {
		t.Errorf("spec String() = %q", s.String())
	}
}

func TestRuleVersionValidation(t *testing.T) {
	for body, want := range map[string]string{
		strings.Replace(goodRule, "  python_package: x\n", "  python_package: x\n  python_package_version: \"<1.5.4\"\n", 1): "",
		strings.Replace(goodRule, "  python_package: x\n", "  python_package: x\n  python_package_version: \"~=1.5\"\n", 1):  "python_package_version",
		strings.Replace(goodRule, "  python_package: x\n", "  env: {A: [\"1\"]}\n  python_package_version: \"<1\"\n", 1):     "needs python_package",
	} {
		_, err := Load(fstest.MapFS{"PH-TEST.yaml": {Data: []byte(body)}})
		switch {
		case want == "" && err != nil:
			t.Errorf("unexpected error %v", err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("want error containing %q, got %v", want, err)
		}
	}
}

// FuzzVersion: parsing never panics, the order is reflexive and
// antisymmetric, and the normalised form parses back to an equal version.
func FuzzVersion(f *testing.F) {
	for _, s := range pep440Order {
		f.Add(s, "1.5.4")
	}
	f.Add("1.0+abc.5", "1.0+5")
	f.Add("v1!2.3rc4.post5.dev6+x.7", "1.0")
	f.Fuzz(func(t *testing.T, a, b string) {
		va, errA := parseVersion(a)
		vb, errB := parseVersion(b)
		if errA != nil || errB != nil {
			return
		}
		if compareVersions(va, va) != 0 {
			t.Fatalf("%q != itself", a)
		}
		if compareVersions(va, vb) != -compareVersions(vb, va) {
			t.Fatalf("compare(%q, %q) not antisymmetric", a, b)
		}
		n, err := parseVersion(va.String())
		if err != nil || compareVersions(n, va) != 0 || n.String() != va.String() {
			t.Fatalf("%q normalises to %q, which doesn't round-trip (%v)", a, va.String(), err)
		}
	})
}

// FuzzSpec: no panic, and an accepted spec's String() parses back to the
// same clauses.
func FuzzSpec(f *testing.F) {
	for _, s := range []string{"<1.5.4", ">=0.4, <1.5.4", "!=1.0.post1", "==1!2.0rc1+abc"} {
		f.Add(s, "1.5.2")
	}
	f.Fuzz(func(t *testing.T, spec, version string) {
		s, err := parseSpec(spec)
		if err != nil {
			return
		}
		again, err := parseSpec(s.String())
		if err != nil || again.String() != s.String() {
			t.Fatalf("%q -> %q doesn't round-trip (%v)", spec, s.String(), err)
		}
		in1, ok1 := s.Contains(version)
		in2, ok2 := again.Contains(version)
		if in1 != in2 || ok1 != ok2 {
			t.Fatalf("round-tripped spec disagrees on %q", version)
		}
		if !ok1 && !in1 {
			t.Fatalf("unparseable version %q reported out of range (must fail closed)", version)
		}
	})
}
