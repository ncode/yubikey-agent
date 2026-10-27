package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func cacheTestSigner(t testing.TB) ssh.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func cacheTestAgent(t testing.TB) (*Agent, *testYubiSource, *Yubi) {
	t.Helper()
	yk := &Yubi{Name: "Yubico test", Serial: 42}
	source := &testYubiSource{
		cards: []string{yk.Name}, devices: map[string]*Yubi{yk.Name: yk},
		keys: map[*Yubi]map[piv.Slot]ssh.Signer{yk: {}},
	}
	for _, slot := range enabledSlots {
		source.keys[yk][slot] = cacheTestSigner(t)
	}
	return &Agent{cardSource: source}, source, yk
}

func TestAgentListCachesMetadataAndCopiesKeys(t *testing.T) {
	a, source, _ := cacheTestAgent(t)
	cardCalls, certCalls := 0, 0
	source.onCards = func() { cardCalls++ }
	source.onPublicKey = func(*Yubi, piv.Slot) { certCalls++ }
	keys, err := a.List()
	if err != nil || len(keys) != 4 {
		t.Fatalf("List = %v, %v", keys, err)
	}
	wantBlob := bytes.Clone(keys[0].Blob)
	wantComment := keys[0].Comment
	keys[0].Blob[0] ^= 0xff
	keys[0].Comment = "mutated"
	keys[1] = nil
	again, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 4 || again[1] == nil || again[0].Comment != wantComment || !bytes.Equal(again[0].Blob, wantBlob) {
		t.Fatalf("caller changed cached keys: %v", again)
	}
	if cardCalls != 1 || certCalls != 4 {
		t.Fatalf("reader probes = %d, certificate reads = %d; want 1, 4", cardCalls, certCalls)
	}
}

func TestAgentListCachesEmptySnapshot(t *testing.T) {
	a, source, yk := cacheTestAgent(t)
	source.keys[yk] = nil
	calls := 0
	source.onCards = func() { calls++ }
	for range 2 {
		keys, err := a.List()
		if err != nil || len(keys) != 0 {
			t.Fatalf("List = %v, %v", keys, err)
		}
	}
	if calls != 1 {
		t.Fatalf("empty cache triggered %d probes, want 1", calls)
	}
}

func TestAgentListRefreshesReadersWithoutRereadingCertificates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, source, _ := cacheTestAgent(t)
		cardCalls, certCalls := 0, 0
		source.onCards = func() { cardCalls++ }
		source.onPublicKey = func(*Yubi, piv.Slot) { certCalls++ }
		if _, err := a.List(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		if _, err := a.List(); err != nil {
			t.Fatal(err)
		}
		if cardCalls != 2 || certCalls != 4 {
			t.Fatalf("reader probes = %d, certificate reads = %d; want 2, 4", cardCalls, certCalls)
		}
	})
}

func TestAgentCacheTracksHotplugAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, source, old := cacheTestAgent(t)
		keys, err := a.List()
		if err != nil {
			t.Fatal(err)
		}
		oldBlob := bytes.Clone(keys[0].Blob)
		replacement := &Yubi{Name: old.Name, Serial: old.Serial}
		source.devices[old.Name] = replacement
		source.keys[replacement] = map[piv.Slot]ssh.Signer{piv.SlotAuthentication: cacheTestSigner(t)}
		source.unhealthy = map[string]bool{old.Name: true}
		time.Sleep(2 * time.Second)
		keys, err = a.List()
		if err != nil || len(keys) != 1 || bytes.Equal(keys[0].Blob, oldBlob) {
			t.Fatalf("reconnected List = %v, %v", keys, err)
		}
		if len(source.closed) != 1 {
			t.Fatalf("closed %v, want old handle", source.closed)
		}
		source.unhealthy = nil
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		source.cards = nil
		if _, err := a.List(); err == nil {
			t.Fatal("List returned keys after Close and unplug")
		}
	})
}

func TestAgentSignPreparesOnlyRequestedSlot(t *testing.T) {
	a, source, yk := cacheTestAgent(t)
	var prepared []piv.Slot
	source.onSigner = func(_ *Yubi, slot piv.Slot) { prepared = append(prepared, slot) }
	key := source.keys[yk][piv.SlotSignature].PublicKey()
	data := []byte("sign only the requested PIV slot")
	sig, err := a.Sign(key, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Verify(data, sig); err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 1 || prepared[0] != piv.SlotSignature {
		t.Fatalf("prepared slots %v, want only 9c", prepared)
	}
	prepared = nil
	if _, err := a.Sign(cacheTestSigner(t).PublicKey(), data); err == nil {
		t.Fatal("signed an unknown key")
	}
	if len(prepared) != 0 {
		t.Fatalf("unknown key prepared slots %v", prepared)
	}
}

func TestAgentListReturnsCachedKeysDuringBlockedHardware(t *testing.T) {
	a, _, _ := cacheTestAgent(t)
	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	// Expired snapshots must also stay available when hardware is occupied.
	a.lastHealthCheck = time.Now().Add(-time.Minute)
	started, release, operationDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(operationDone)
		_, _ = a.runSignOperation(context.Background(), func() (*ssh.Signature, error) {
			close(started)
			<-release
			return nil, nil
		})
	}()
	<-started
	type result struct {
		keys []*sshagent.Key
		err  error
	}
	listed := make(chan result, 1)
	go func() { keys, err := a.List(); listed <- result{keys, err} }()
	var got result
	responsive := false
	select {
	case got = <-listed:
		responsive = true
	case <-time.After(time.Second):
	}
	close(release)
	<-operationDone
	if !responsive {
		<-listed
		t.Fatal("cached List waited for blocked hardware")
	}
	if got.err != nil || len(got.keys) != len(keys) {
		t.Fatalf("cached List = %v, %v", got.keys, got.err)
	}
}

func TestAgentTimeoutInvalidatesCacheOnlyAfterHardwareReturns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, source, _ := cacheTestAgent(t)
		if _, err := a.List(); err != nil {
			t.Fatal(err)
		}
		release := make(chan struct{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := a.runSignOperation(ctx, func() (*ssh.Signature, error) { <-release; return nil, nil })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		// Read the snapshot directly: even a stale listing is safe public data.
		a.cacheMu.RLock()
		cached := len(a.agentKeys)
		a.cacheMu.RUnlock()
		if cached != 4 || len(source.closed) != 0 {
			t.Fatal("discarded state before hardware returned")
		}
		close(release)
		synctest.Wait()
		if len(source.closed) != 1 {
			t.Fatalf("closed %v", source.closed)
		}
		a.cacheMu.RLock()
		cached = len(a.agentKeys)
		a.cacheMu.RUnlock()
		if cached != 0 {
			t.Fatal("retained keys after timeout cleanup")
		}
	})
}

func BenchmarkAgentListFromCache(b *testing.B) {
	a, _, _ := cacheTestAgent(b)
	if _, err := a.List(); err != nil {
		b.Fatal(err)
	}
	// Keep this benchmark focused on copying the snapshot, excluding PC/SC.
	a.lastHealthCheck = time.Now().Add(time.Hour)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.List(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestInitialListWaitHasDeadlineWhileHardwareIsBusy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &Agent{}
		started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			_, _ = a.runSignOperation(context.Background(), func() (*ssh.Signature, error) {
				close(started)
				<-release
				return nil, nil
			})
		}()
		<-started
		_, err := a.List()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("initial List error = %v", err)
		}
		close(release)
		<-done
	})
}

func TestCloseWaitsForHardwareBeforeReleasingHandles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, source, _ := cacheTestAgent(t)
		if _, err := a.List(); err != nil {
			t.Fatal(err)
		}
		started, release, done, closed := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			_, _ = a.runSignOperation(context.Background(), func() (*ssh.Signature, error) {
				close(started)
				<-release
				return nil, nil
			})
		}()
		<-started
		go func() { _ = a.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Error("Close returned before hardware completed")
		default:
		}
		if len(source.closed) != 0 {
			t.Error("closed in-flight device")
		}
		if keys, err := a.List(); err != nil || len(keys) != 4 {
			t.Errorf("List while Close waits = %v, %v", keys, err)
		}
		close(release)
		<-done
		<-closed
		if len(source.closed) != 1 {
			t.Errorf("closed %v", source.closed)
		}
	})
}

func BenchmarkResolveKeyFromCache(b *testing.B) {
	a, source, yk := cacheTestAgent(b)
	if _, err := a.List(); err != nil {
		b.Fatal(err)
	}
	key := source.keys[yk][piv.SlotSignature].PublicKey()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.resolveKey(key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkListCachedKeys(b *testing.B) {
	a, _, _ := cacheTestAgent(b)
	if _, err := a.List(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = a.cachedKeys()
	}
}

func TestTransientCertificateErrorDoesNotCacheMissingKeys(t *testing.T) {
	a, source, _ := cacheTestAgent(t)
	transient := errors.New("temporary PC/SC certificate read failure")
	source.publicErr = transient
	if _, err := a.List(); !errors.Is(err, transient) {
		t.Fatalf("List error = %v, want temporary failure", err)
	}
	source.publicErr = nil
	keys, err := a.List()
	if err != nil || len(keys) != 4 {
		t.Fatalf("List after recovery = %v, %v", keys, err)
	}
}
