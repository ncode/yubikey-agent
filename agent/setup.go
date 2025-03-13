// Copyright 2020 Google LLC
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
	"runtime/debug"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func init() {
	if Version != "" {
		return
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		Version = buildInfo.Main.Version
		return
	}
	Version = "(unknown version)"
}

func RunReset(yk *piv.YubiKey) {
	fmt.Println("Resetting YubiKey PIV applet...")
	if err := yk.Reset(); err != nil {
		log.Fatalln("Failed to reset YubiKey:", err)
	}
}

// generateAndStoreSSHKey generates the key and store on the given slot and apply the expected touch policy
func generateAndStoreSSHKey(yk *piv.YubiKey, key []byte, slot piv.Slot, policy piv.PINPolicy, touch piv.TouchPolicy) error {
	pub, err := yk.GenerateKey(key, slot, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   policy,
		TouchPolicy: touch,
	})
	if err != nil {
		return fmt.Errorf("Failed to generate key for slot %x: %s", slot, err.Error())
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate parent key for slot %x: %s", slot, err.Error())
	}
	parent := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"yubikey-agent"},
			OrganizationalUnit: []string{Version},
		},
		PublicKey: priv.Public(),
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "SSH key",
		},
		NotAfter:     time.Now().AddDate(42, 0, 0),
		NotBefore:    time.Now(),
		SerialNumber: randomSerialNumber(),
		KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return fmt.Errorf("Failed to generate certificate for slot %x: %s", slot, err.Error())
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("Failed to parse certificate for slot %x: %s", slot, err.Error())
	}
	if err := yk.SetCertificate(key, slot, cert); err != nil {
		return fmt.Errorf("Failed to store certificate on slot %x: %s", slot, err.Error())
	}

	sshKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("Failed to generate public key for slot %x: %s", slot, err.Error())
	}

	fmt.Printf("🔑 Here's your new shiny SSH public key for slot %x:\n", slot)
	os.Stdout.Write(ssh.MarshalAuthorizedKey(sshKey))
	fmt.Println("")

	return nil
}

func RunSetup(yk *piv.YubiKey) {
	log.SetFlags(0)
	if _, err := yk.Certificate(piv.SlotAuthentication); err == nil {
		log.Println("‼️  This YubiKey looks already setup")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠⚠")
	} else if !errors.Is(err, piv.ErrNotFound) {
		log.Fatalln("Failed to access authentication slot:", err)
	}

	fmt.Println("🔐 The PIN is up to 8 numbers, letters, or symbols. Not just numbers!")
	fmt.Println("❌ The key will be lost if the PIN and PUK are locked after 3 incorrect tries.")
	fmt.Println("")
	fmt.Print("Choose a new PIN/PUK: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if len(pin) == 0 || len(pin) != 8 {
		log.Fatalln("The PIN needs to be 8 characters.")
	}
	fmt.Print("Repeat PIN/PUK: ")
	repeat, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	} else if !bytes.Equal(repeat, pin) {
		log.Fatalln("PINs don't match!")
	}

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

	var key []byte
	if _, err := rand.Read(key[:]); err != nil {
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

	err = generateAndStoreSSHKey(yk, key, piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyAlways)
	if err != nil {
		log.Fatal(err)
	}

	err = generateAndStoreSSHKey(yk, key, piv.SlotSignature, piv.PINPolicyAlways, piv.TouchPolicyAlways)
	if err != nil {
		log.Fatal(err)
	}

	err = generateAndStoreSSHKey(yk, key, piv.SlotCardAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever)
	if err != nil {
		log.Fatal(err)
	}

	err = generateAndStoreSSHKey(yk, key, piv.SlotKeyManagement, piv.PINPolicyNever, piv.TouchPolicyNever)
	if err != nil {
		log.Fatal(err)
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

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalln("Failed to generate serial number:", err)
	}
	return serialNumber
}
