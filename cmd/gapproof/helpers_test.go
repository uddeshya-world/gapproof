package main

import (
	"errors"

	"github.com/spf13/cobra"
)

type cobraCmd = cobra.Command

var errPlain = errors.New("plain failure")
