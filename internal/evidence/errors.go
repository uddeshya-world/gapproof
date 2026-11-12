package evidence

import "fmt"

// UsageError is a problem with what the user supplied (a scope or waivers
// file, a waiver that matches several findings). The CLI maps it to exit 2.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func usagef(format string, a ...any) error { return &UsageError{fmt.Sprintf(format, a...)} }
