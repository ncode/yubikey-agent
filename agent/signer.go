package agent

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentSigner deliberately holds no device handle. All signing must pass
// through the same serialization and deadline handling as socket requests.
type agentSigner struct {
	a   *Agent
	key ssh.PublicKey
}

var _ ssh.AlgorithmSigner = agentSigner{}

func (s agentSigner) PublicKey() ssh.PublicKey { return s.key }

func (s agentSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.a.Sign(s.key, data)
}

func (s agentSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	var flags agent.SignatureFlags
	switch {
	case algorithm == "" || algorithm == s.key.Type():
	case s.key.Type() == ssh.KeyAlgoRSA && algorithm == ssh.KeyAlgoRSASHA256:
		flags = agent.SignatureFlagRsaSha256
	case s.key.Type() == ssh.KeyAlgoRSA && algorithm == ssh.KeyAlgoRSASHA512:
		flags = agent.SignatureFlagRsaSha512
	default:
		return nil, fmt.Errorf("unsupported signature algorithm %q for %s", algorithm, s.key.Type())
	}
	return s.a.SignWithFlags(s.key, data, flags)
}
