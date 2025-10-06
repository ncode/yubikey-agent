// Copyright 2020 Google LLC
// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	// RequiredPINLength is the required length for YubiKey PINs
	RequiredPINLength = 8

	// CertificateValidityYears is how many years certificates are valid for
	CertificateValidityYears = 42
)

// slotConfig defines the configuration for a PIV slot
type slotConfig struct {
	slot        piv.Slot
	pinPolicy   piv.PINPolicy
	touchPolicy piv.TouchPolicy
}

// defaultSlotConfigs are the default configurations for PIV slots
var defaultSlotConfigs = []slotConfig{
	{piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyAlways},
	{piv.SlotSignature, piv.PINPolicyAlways, piv.TouchPolicyAlways},
	{piv.SlotCardAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever},
	{piv.SlotKeyManagement, piv.PINPolicyNever, piv.TouchPolicyNever},
}

// Version contains the build version of yubikey-agent, set at build time.
var Version string

// readPINWithConfirmation prompts the user to enter a PIN and confirm it.
// This is an interactive function that exits on error using log.Fatal.
func readPINWithConfirmation() []byte {
	fmt.Println("🔐 The PIN is up to 8 numbers, letters, or symbols. Not just numbers!")
	fmt.Println("❌ The key will be lost if the PIN and PUK are locked after 3 incorrect tries.")
	fmt.Println("")
	fmt.Print("Choose a new PIN/PUK: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if len(pin) == 0 || len(pin) != RequiredPINLength {
		log.Fatalf("The PIN needs to be %d characters.\n", RequiredPINLength)
	}
	fmt.Print("Repeat PIN/PUK: ")
	repeat, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if !bytes.Equal(repeat, pin) {
		log.Fatalln("PINs don't match!")
	}
	return pin
}

// getSingleYubiKey loads YubiKeys (respecting --serial) and ensures exactly one is found.
// Returns the YubiKey and nil if successful, or nil and an error if failed.
func GetSingleYubiKey() (*Yubi, error) {
	yks, err := LoadYubiKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load YubiKeys: %w", err)
	}

	if len(yks) == 0 {
		return nil, errors.New("no YubiKey found")
	}

	if len(yks) > 1 {
		return nil, errors.New("multiple YubiKeys found; please specify --serial or remove extra devices")
	}

	return yks[0], nil
}

// RunSetup sets up all four main PIV slots on a single YubiKey, generating
// SSH-usable certificates in each. This function expects you’ve already
// selected your one YubiKey, e.g. via RunSetupSelected().
func RunSetup(yk *piv.YubiKey) {
	log.SetFlags(0)
	if _, err := yk.Certificate(piv.SlotAuthentication); err == nil {
		log.Println("‼️  This YubiKey looks already set up")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠⚠")
	} else if !errors.Is(err, piv.ErrNotFound) {
		log.Fatalln("Failed to access authentication slot:", err)
	}

	pin := readPINWithConfirmation()

	fmt.Println("")
	fmt.Println("🧪 Reticulating splines...")

	fmt.Println("")
	fmt.Println("Configuring slots following the definition from yubico-piv-tool")
	fmt.Println("details https://developers.yubico.com/PIV/Introduction/Certificate_slots.html")
	fmt.Println(" - 9a is for PIV Authentication (PIN Once)")
	fmt.Println(" - 9c is for Digital Signature (PIN always checked)")
	fmt.Println(" - 9d is for Key Management (PIN Once)")
	fmt.Println(" - 9e is for Card Authentication (PIN never checked)")
	fmt.Println("")

	// Generate a random new management key
	key := make([]byte, 24)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	if err := yk.SetManagementKey(piv.DefaultManagementKey, key); err != nil {
		log.Println("‼️ The default Management Key did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetMetadata(key, &piv.Metadata{
		ManagementKey: &key,
	}); err != nil {
		log.Fatalln("Failed to store the Management Key on the device:", err)
	}
	if err := yk.SetPIN(piv.DefaultPIN, string(pin)); err != nil {
		log.Println("‼️ The default PIN did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetPUK(piv.DefaultPUK, string(pin)); err != nil {
		log.Println("‼️ The default PUK did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}

	// Generate keys for all configured slots
	for _, cfg := range defaultSlotConfigs {
		if err := generateAndStoreSSHKey(yk, key, cfg.slot, cfg.pinPolicy, cfg.touchPolicy); err != nil {
			log.Fatalf("Failed to configure slot %x: %v", cfg.slot.Key, err)
		}
	}

	fmt.Println("")
	fmt.Println("✅ Done! This YubiKey is secured and ready to go.")
	fmt.Println("🤏 When the YubiKey blinks, touch it to authorize the login.")
	fmt.Println("")
	fmt.Println("Next steps: ensure yubikey-agent is running via launchd/systemd/...,")
	fmt.Println(`set the SSH_AUTH_SOCK environment variable, and test with "ssh-add -L"`)
	fmt.Println("")
	fmt.Println("💭 Remember: everything breaks, have a backup plan for when this YubiKey does.")
}

func randomSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}

// generateAndStoreSSHKey generates a new EC key on the given slot (with the
// specified PIN/touch policies), creates a self-signed certificate for it,
// and prints out the SSH public key.
func generateAndStoreSSHKey(yk *piv.YubiKey, key []byte, slot piv.Slot, policy piv.PINPolicy, touch piv.TouchPolicy) error {
	pub, err := yk.GenerateKey(key, slot, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   policy,
		TouchPolicy: touch,
	})
	if err != nil {
		return fmt.Errorf("failed to generate key for slot %x: %w", slot.Key, err)
	}

	// Create a dummy self-signed cert:
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate parent key for slot %x: %w", slot.Key, err)
	}
	parent := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"yubikey-agent"},
			OrganizationalUnit: []string{Version},
		},
		PublicKey: priv.Public(),
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "SSH key",
		},
		NotAfter:     time.Now().AddDate(CertificateValidityYears, 0, 0),
		NotBefore:    time.Now(),
		SerialNumber: serial,
		KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return fmt.Errorf("failed to generate certificate for slot %x: %w", slot.Key, err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate for slot %x: %w", slot.Key, err)
	}
	if err := yk.SetCertificate(key, slot, cert); err != nil {
		return fmt.Errorf("failed to store certificate on slot %x: %w", slot.Key, err)
	}

	sshKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to generate public key for slot %x: %w", slot.Key, err)
	}

	fmt.Printf("🔑 Here's your new shiny SSH public key for slot %x:\n", slot.Key)
	os.Stdout.Write(ssh.MarshalAuthorizedKey(sshKey))
	fmt.Println("")

	return nil
}

// SetupSlot configures (or re-configures) a single PIV slot with a specified
// PIN policy and touch policy. Demonstrates a more “incremental” approach,
// rather than setting up all slots at once.
//
// If a management key is not yet stored in metadata, it will prompt for a PIN
// (resetting from defaults). Otherwise, it reuses the existing management key.
func SetupSlot(yk *piv.YubiKey, slot piv.Slot, pinPolicy piv.PINPolicy, touchPolicy piv.TouchPolicy) {
	log.SetFlags(0)

	var managementKey []byte

	// Attempt to load an existing management key from the YubiKey’s metadata
	metadata, err := yk.Metadata(string(piv.DefaultManagementKey))
	if err == nil && metadata.ManagementKey != nil {
		managementKey = *metadata.ManagementKey
		fmt.Println("🔐 Using existing management key from YubiKey metadata")
	} else {
		// Need to set up the management key, PIN, and PUK from defaults
		fmt.Println("🔐 No management key found in metadata. Need to set up YubiKey first.")
		fmt.Println("")
		pin := readPINWithConfirmation()

		fmt.Println("")
		fmt.Println("🧪 Setting up management key and PIN...")

		managementKey = make([]byte, 24)
		if _, err := rand.Read(managementKey); err != nil {
			log.Fatal(err)
		}

		// Update the YubiKey from default credentials → new random management key
		if err := yk.SetManagementKey(piv.DefaultManagementKey, managementKey); err != nil {
			log.Println("‼️ The default Management Key did not work")
			log.Println("")
			log.Println("If you know what you're doing, reset PIN, PUK, and")
			log.Println("Management Key to the defaults before retrying.")
			log.Println("")
			log.Println("If you want to wipe all PIV keys and start fresh,")
			log.Fatalln("use setup --really-delete-all-piv-keys ⚠️")
		}

		// Store management key in protected metadata
		if err := yk.SetMetadata(managementKey, &piv.Metadata{
			ManagementKey: &managementKey,
		}); err != nil {
			log.Fatalln("Failed to store the Management Key on the device:", err)
		}

		// Update PIN and PUK from default
		if err := yk.SetPIN(piv.DefaultPIN, string(pin)); err != nil {
			log.Println("‼️ The default PIN did not work")
			log.Println("")
			log.Println("If you know what you're doing, reset PIN, PUK, and")
			log.Println("Management Key to the defaults before retrying.")
			log.Println("")
			log.Println("If you want to wipe all PIV keys and start fresh,")
			log.Fatalln("use setup --really-delete-all-piv-keys ⚠️")
		}
		if err := yk.SetPUK(piv.DefaultPUK, string(pin)); err != nil {
			log.Println("‼️ The default PUK did not work")
			log.Println("")
			log.Println("If you know what you're doing, reset PIN, PUK, and")
			log.Println("Management Key to the defaults before retrying.")
			log.Println("")
			log.Println("If you want to wipe all PIV keys and start fresh,")
			log.Fatalln("use setup --really-delete-all-piv-keys ⚠️")
		}
	}

	// Generate/store the key in the given slot
	fmt.Printf("🔑 Generating SSH key for slot %x with PIN policy %v and touch policy %v\n",
		slot.Key, pinPolicy, touchPolicy)

	if err := generateAndStoreSSHKey(yk, managementKey, slot, pinPolicy, touchPolicy); err != nil {
		log.Fatal(err)
	}

	fmt.Println("")
	fmt.Printf("✅ Done! Slot %x is configured with the specified policies.\n", slot.Key)
	if touchPolicy == piv.TouchPolicyAlways {
		fmt.Println("🤏 When the YubiKey blinks, touch it to authorize the login.")
	}
	fmt.Println("")
	fmt.Println("Next steps: ensure yubikey-agent is running, and test with \"ssh-add -L\"")
}
