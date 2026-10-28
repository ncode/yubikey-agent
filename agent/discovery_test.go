package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type testYubiSource struct {
	publicErr   error
	keys        map[*Yubi]map[piv.Slot]ssh.Signer
	onPublicKey func(*Yubi, piv.Slot)
	onSigner    func(*Yubi, piv.Slot)

	cards          []string
	devices        map[string]*Yubi
	unhealthy      map[string]bool
	opened, closed []string
	err            error
	onOpen         func()
	onCards        func()
}

func (s *testYubiSource) Cards() ([]string, error) {
	if s.onCards != nil {
		s.onCards()
	}
	return s.cards, s.err
}
func (s *testYubiSource) Open(card string, serial uint32) (*Yubi, error) {
	s.opened = append(s.opened, card)
	if s.onOpen != nil {
		s.onOpen()
	}
	yk := s.devices[card]
	if yk != nil && serial != 0 && yk.Serial != serial {
		return nil, nil
	}
	return yk, nil
}
func (s *testYubiSource) Healthy(yk *Yubi) bool { return !s.unhealthy[yk.Name] }
func (s *testYubiSource) Close(yk *Yubi) error  { s.closed = append(s.closed, yk.Name); return nil }

func (s *testYubiSource) PublicKey(yk *Yubi, slot piv.Slot) (ssh.PublicKey, error) {
	if s.onPublicKey != nil {
		s.onPublicKey(yk, slot)
	}
	if s.publicErr != nil {
		return nil, s.publicErr
	}
	if signer := s.keys[yk][slot]; signer != nil {
		return signer.PublicKey(), nil
	}
	return nil, piv.ErrNotFound
}
func (s *testYubiSource) Signer(yk *Yubi, slot piv.Slot, public ssh.PublicKey, prompt func() (string, error)) (ssh.Signer, error) {
	if s.onSigner != nil {
		s.onSigner(yk, slot)
	}
	signer := s.keys[yk][slot]
	if signer == nil {
		return nil, piv.ErrNotFound
	}
	return signer, nil
}

func TestEnsureYKDiscoversAdditionalDevices(t *testing.T) {
	viper.Set("serial", uint32(0))
	defer viper.Set("serial", nil)
	aKey, bKey := &Yubi{Name: "A", Serial: 1}, &Yubi{Name: "B", Serial: 2}
	source := &testYubiSource{cards: []string{"A", "B"}, devices: map[string]*Yubi{"A": aKey, "B": bKey}}
	a := &Agent{yks: []*Yubi{aKey}, cardSource: source}
	if err := a.ensureYK(); err != nil {
		t.Fatal(err)
	}
	if len(a.yks) != 2 {
		t.Fatalf("discovered %d devices, want 2", len(a.yks))
	}
	if len(source.opened) != 1 || source.opened[0] != "B" || len(source.closed) != 0 {
		t.Fatalf("opened %v, closed %v; healthy A must stay open", source.opened, source.closed)
	}
	if err := a.ensureYK(); err != nil {
		t.Fatal(err)
	}
	if len(source.opened) != 1 {
		t.Fatalf("reopened cached devices: %v", source.opened)
	}
}

func TestLoadYubiKeysClosesDeviceWhenFinalOpenIsCanceled(t *testing.T) {
	viper.Set("serial", uint32(0))
	defer viper.Set("serial", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &testYubiSource{cards: []string{"A"}, devices: map[string]*Yubi{"A": {Name: "A"}}, onOpen: cancel}
	_, err := loadYubiKeysContext(ctx, source)
	if !errors.Is(err, context.Canceled) || len(source.closed) != 1 {
		t.Fatalf("error = %v, closed = %v", err, source.closed)
	}
}

func TestEnsureYKReconcilesCachedDevices(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		cards                             []string
		serial                            uint32
		unhealthy                         bool
		readerErr                         error
		wantCount, wantClosed, wantOpened int
		wantError                         bool
	}{
		{name: "removed device", wantClosed: 1, wantError: true},
		{name: "reconnected reader", cards: []string{"A"}, unhealthy: true, wantCount: 1, wantClosed: 1, wantOpened: 1},
		{name: "serial filter", cards: []string{"A", "B"}, serial: 1, wantCount: 1},
		{name: "reader error preserves handles", readerErr: errors.New("PCSC unavailable"), wantCount: 1, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("serial", tc.serial)
			defer viper.Set("serial", nil)
			old := &Yubi{Name: "A", Serial: 1}
			source := &testYubiSource{cards: tc.cards, devices: map[string]*Yubi{"A": {Name: "A", Serial: 1}, "B": {Name: "B", Serial: 2}}, unhealthy: map[string]bool{"A": tc.unhealthy}, err: tc.readerErr}
			a := &Agent{yks: []*Yubi{old}, cardSource: source}
			err := a.ensureYK()
			if (err != nil) != tc.wantError || len(a.yks) != tc.wantCount || len(source.closed) != tc.wantClosed || len(source.opened) != tc.wantOpened {
				t.Fatalf("error = %v, devices = %d, closed = %v, opened = %v", err, len(a.yks), source.closed, source.opened)
			}
			if tc.unhealthy && a.yks[0] == old {
				t.Fatal("retained the unhealthy handle")
			}
		})
	}
}
