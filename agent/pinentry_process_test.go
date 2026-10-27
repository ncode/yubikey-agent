package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestPINPromptCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := getPIN(ctx, 123, 3); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestPINEntryProcessCancellation(t *testing.T) {
	if os.Getenv("YUBIKEY_AGENT_PINENTRY_HELPER") == "1" {
		fmt.Println("READY")
		var input string
		_, _ = fmt.Fscanln(os.Stdin, &input)
		os.Exit(0)
	}
	t.Setenv("YUBIKEY_AGENT_PINENTRY_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &pinentryProcess{ctx: ctx}
	if err := p.Start(executable, []string{"-test.run=^TestPINEntryProcessCancellation$"}); err != nil {
		t.Fatal(err)
	}
	line, _, err := p.ReadLine()
	if err != nil || string(line) != "READY" {
		t.Fatalf("helper response = %q, %v", line, err)
	}
	cancel()
	if _, _, err := p.ReadLine(); err == nil {
		t.Error("canceled process kept its output open")
	}
	_ = p.Close() // Cancellation deliberately kills the helper.
}
