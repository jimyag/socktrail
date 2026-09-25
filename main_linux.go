package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jimyag/socktrail/internal/app"
)

func main() {
	if err := app.Run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "socktrail:", err)
		os.Exit(1)
	}
}
