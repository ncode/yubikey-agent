//go:build !darwin

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPINEntryDoesNotReplayExternalCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	program := filepath.Join(dir, "pinentry")
	// Model a frontend with a stale password-store entry. It returns that
	// value only when the client explicitly enables external caching.
	script := `#!/bin/sh
printf 'OK pinentry test server\n'
cache=0
while IFS= read -r line; do
  case "$line" in
    'OPTION allow-external-password-cache') cache=1; printf 'OK\n';;
    GETPIN)
      if [ "$cache" = 1 ]; then
        printf 'S PASSWORD_FROM_CACHE\nD 00000000\nOK\n'
      else
        printf 'D 12345678\nOK\n'
      fi;;
    BYE) printf 'OK\n'; exit 0;;
    *) printf 'OK\n';;
  esac
done
`
	if err := os.WriteFile(program, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(dir, ".gnupg")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "gpg-agent.conf"), []byte("pinentry-program "+program+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, remaining := range []int{3, 2, 1} {
		pin, err := getPIN(context.Background(), 123, remaining)
		if err != nil {
			t.Fatal(err)
		}
		if pin != "12345678" {
			t.Errorf("%d tries remaining: returned a stale cached PIN instead of fresh input", remaining)
		}
	}
}
