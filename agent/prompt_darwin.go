// Copyright 2020 Google LLC
// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"text/template"
)

var scriptTemplate = template.Must(template.New("script").Parse(`
var app = Application.currentApplication()
app.includeStandardAdditions = true
app.displayDialog(
	"YubiKey serial number: {{ .Serial }} " +
	"({{ .Tries }} tries remaining)\n\n" +
	"Please enter your PIN:", {
    defaultAnswer: "",
	withTitle: "yubikey-agent PIN prompt",
    buttons: ["Cancel", "OK"],
    defaultButton: "OK",
	cancelButton: "Cancel",
    hiddenAnswer: true,
})`))

func getPIN(ctx context.Context, serial uint32, retries int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	script := new(bytes.Buffer)
	if err := scriptTemplate.Execute(script, map[string]interface{}{
		"Serial": serial, "Tries": retries,
	}); err != nil {
		return "", err
	}

	c := exec.CommandContext(ctx, "osascript", "-s", "se", "-l", "JavaScript")
	c.Stdin = script
	out, err := c.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("failed to execute osascript: %w", err)
	}
	var x struct {
		PIN string `json:"textReturned"`
	}
	if err := json.Unmarshal(out, &x); err != nil {
		return "", fmt.Errorf("failed to parse osascript output: %v", err)
	}
	return x.PIN, nil
}
