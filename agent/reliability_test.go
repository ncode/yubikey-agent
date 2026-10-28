package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
)

func TestAuthErrorValues(t *testing.T) {
	for _, err := range []error{piv.AuthErr{Retries: 2}, fmt.Errorf("verify: %w", piv.AuthErr{Retries: 2})} {
		if got := isRetriableAuthError(err); got != 2 {
			t.Errorf("isRetriableAuthError(%T) = %d, want 2", err, got)
		}
	}
}

func TestCanceledPreparationDoesNotSign(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		attempts := 0
		_, _ = signWithRetry(ctx, func() ([]ssh.Signer, error) {
			cancel()
			return nil, nil
		}, func([]ssh.Signer) (*ssh.Signature, error) {
			attempts++
			return nil, nil
		})
		synctest.Wait()
		if attempts != 0 {
			t.Fatalf("started %d signing attempts after cancellation", attempts)
		}
	})
}

func TestSignTimeoutRetainsExclusiveDeviceOwnership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &Agent{}
		release := make(chan struct{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := a.runSignOperation(ctx, func() (*ssh.Signature, error) {
			<-release
			return nil, nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error = %v", err)
		}
		if a.mu.TryLock() {
			a.mu.Unlock()
			t.Error("device mutex released while the card operation is still running")
		}
		secondCtx, secondCancel := context.WithTimeout(context.Background(), time.Second)
		defer secondCancel()
		called := false
		_, err = a.runSignOperation(secondCtx, func() (*ssh.Signature, error) {
			called = true
			return nil, nil
		})
		if !errors.Is(err, context.DeadlineExceeded) || called {
			t.Errorf("second request: error = %v, called = %v", err, called)
		}
		close(release)
		synctest.Wait()
		if err := a.Close(); err != nil {
			t.Error(err)
		}
		_, err = a.runSignOperation(context.Background(), func() (*ssh.Signature, error) { return &ssh.Signature{}, nil })
		if err != nil {
			t.Errorf("request after recovery: %v", err)
		}
	})
}

func TestSignTimeoutIncludesPreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &Agent{}
		release := make(chan struct{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		attempts := 0
		_, err := a.runSignOperation(ctx, func() (*ssh.Signature, error) {
			return signWithRetry(ctx, func() ([]ssh.Signer, error) {
				<-release
				return nil, nil
			}, func([]ssh.Signer) (*ssh.Signature, error) {
				attempts++
				return nil, nil
			})
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error = %v", err)
		}
		close(release)
		synctest.Wait()
		if attempts != 0 {
			t.Errorf("%d attempts started after preparation timed out", attempts)
		}
	})
}

func TestSignTimeoutWhileWaitingForMutex(t *testing.T) {
	a := &Agent{}
	a.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	called := false
	_, err := a.runSignOperation(ctx, func() (*ssh.Signature, error) { called = true; return nil, nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v", err)
	}
	a.mu.Unlock()
	// Wait for the canceled worker to release the gate before inspecting
	// callback state. Mutex waits cannot use synctest's virtual clock.
	_, _ = a.runSignOperation(context.Background(), func() (*ssh.Signature, error) { return nil, nil })
	if called {
		t.Error("started device work after timeout")
	}
}

type hardwarePINSigner struct {
	key    ssh.PublicKey
	verify func() error
}

func (s hardwarePINSigner) PublicKey() ssh.PublicKey                       { return s.key }
func (s hardwarePINSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) { return nil, s.verify() }
func (s hardwarePINSigner) SignWithAlgorithm(io.Reader, []byte, string) (*ssh.Signature, error) {
	return nil, s.verify()
}

func TestHardwarePINVerificationCannotBeCanceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		yk := &Yubi{Name: "hardware PIN verification"}
		source := &testYubiSource{}
		a := &Agent{yks: []*Yubi{yk}, cardSource: source}
		key := &mockPublicKey{keyType: ssh.KeyAlgoECDSA256}
		releaseHardware := make(chan struct{})
		attempts := 0
		signer := hardwarePINSigner{key: key, verify: func() error {
			attempts++
			<-releaseHardware // Models an uncancellable PIN VERIFY APDU.
			return piv.AuthErr{Retries: 2}
		}}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := a.runSignOperation(ctx, func() (*ssh.Signature, error) {
			return signWithRetry(ctx,
				func() ([]ssh.Signer, error) { return []ssh.Signer{signer}, nil },
				func(signers []ssh.Signer) (*ssh.Signature, error) {
					return a.performSignature(signers, key, nil, key.Type())
				})
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error = %v", err)
		}
		if len(source.closed) != 0 {
			t.Error("closed hardware while PIN verification was still in flight")
		}
		if a.mu.TryLock() {
			a.mu.Unlock()
			t.Error("released hardware ownership while PIN verification was in flight")
		}
		close(releaseHardware)
		synctest.Wait()
		if attempts != 1 {
			t.Errorf("retried PIN verification %d times after timeout", attempts)
		}
		if len(source.closed) != 1 || len(a.yks) != 0 {
			t.Error("did not release cached handles after hardware verification finished")
		}
	})
}

func TestReturnedSignerHonorsHardwareOwnership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &Agent{}
		release := make(chan struct{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = a.runSignOperation(ctx, func() (*ssh.Signature, error) { <-release; return nil, nil })
		signer := agentSigner{a: a, key: &mockPublicKey{keyType: ssh.KeyAlgoECDSA256}}
		_, err := signer.Sign(nil, []byte("test"))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("signer bypassed the busy hardware gate: %v", err)
		}
		close(release)
		synctest.Wait()
	})
}

func TestSignWithFlagsDeadlineIncludesDiscovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		source := &testYubiSource{cards: []string{"A"}, onCards: func() { <-release }}
		a := &Agent{cardSource: source}
		started := time.Now()
		_, err := a.SignWithFlags(&mockPublicKey{keyType: ssh.KeyAlgoECDSA256}, []byte("test"), 0)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != SignOperationTimeout {
			t.Errorf("error = %v after %v", err, time.Since(started))
		}
		if a.mu.TryLock() {
			a.mu.Unlock()
			t.Error("released device ownership during discovery")
		}
		close(release)
		synctest.Wait()
		if len(source.opened) != 0 {
			t.Errorf("opened devices after timeout: %v", source.opened)
		}
	})
}

type trackingConn struct {
	net.Conn
	closed bool
}

func (c *trackingConn) Close() error {
	c.closed = true
	return c.Conn.Close()
}

func TestServeConnClosesConnection(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	client.Close()
	c := &trackingConn{Conn: server}
	new(Agent).serveConn(c)
	if !c.closed {
		t.Fatal("serveConn returned without closing the connection")
	}
}

func TestTouchNotificationLifecycle(t *testing.T) {
	a := &Agent{}
	for range 1000 {
		_, cancel := a.setupTouchNotification(context.Background())
		cancel()
	}
}
