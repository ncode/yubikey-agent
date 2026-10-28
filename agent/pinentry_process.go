package agent

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
)

// pinentryProcess makes the pinentry client's blocking reads cancellable by
// tying the subprocess lifetime to the signing request.
type pinentryProcess struct {
	ctx    context.Context
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func (p *pinentryProcess) Start(name string, args []string) error {
	p.cmd = exec.CommandContext(p.ctx, name, args...)
	stdin, err := p.cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return err
	}
	if err := p.cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return err
	}
	p.stdin, p.stdout = stdin, bufio.NewReader(stdout)
	return nil
}

func (p *pinentryProcess) Write(data []byte) (int, error)  { return p.stdin.Write(data) }
func (p *pinentryProcess) ReadLine() ([]byte, bool, error) { return p.stdout.ReadLine() }
func (p *pinentryProcess) Close() error                    { return errors.Join(p.stdin.Close(), p.cmd.Wait()) }
