// Command abctl is an interactive terminal UI for inspecting AuthBridge's
// in-memory session store. It connects to the session API exposed by a
// sidecar (default http://localhost:9094, reached via kubectl port-forward)
// and renders three panes: active sessions, per-session event stream, and
// event JSON detail. See README.md for usage.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kagenti/kagenti-extensions/authbridge/cmd/abctl/tui"
)

func main() {
	endpoint := flag.String("endpoint", "http://localhost:9094",
		"AuthBridge session API URL (typically via kubectl port-forward)")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Translate Ctrl-C / SIGTERM into ctx cancellation. The TUI also handles
	// q / Ctrl+C directly; this covers SIGTERM from a supervisor and is
	// harmless belt-and-braces for signal delivery.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	if err := tui.Run(ctx, *endpoint); err != nil {
		fmt.Fprintf(os.Stderr, "abctl: %v\n", err)
		os.Exit(1)
	}
}
