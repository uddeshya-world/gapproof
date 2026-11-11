package detid

import (
	"regexp"
	"testing"
)

var oscalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestUUID(t *testing.T) {
	a := UUID("ns", "ab", "c")
	if !oscalUUID.MatchString(a) {
		t.Fatalf("%q is not a version-5-shaped UUID", a)
	}
	if a != UUID("ns", "ab", "c") {
		t.Error("not deterministic")
	}
	for _, other := range []string{UUID("ns", "a", "bc"), UUID("ns2", "ab", "c"), UUID("ns", "abc")} {
		if other == a {
			t.Errorf("collision: %s", other)
		}
	}
	// Pinned so an accidental change of derivation (which would change every
	// published document ID) fails loudly.
	if got, want := UUID("gapproof"), "169141d3-b7f1-565e-a8c7-2deaf3598c76"; got != want {
		t.Errorf("UUID derivation changed: got %s, want %s", got, want)
	}
}
