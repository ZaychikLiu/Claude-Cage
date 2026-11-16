//go:build darwin && arm64 && cgo && !no_vz

package maclogin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

type passwordProbeInput struct{ bytes.Buffer }

func (*passwordProbeInput) Close() error { return nil }

func TestMaintenancePasswordProbeUsesFixedPrivateStreamRequest(t *testing.T) {
	target := passwordTarget{maintenanceWindow: maintenanceFixture(), SelectionRequired: true}
	first, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	target.Window++
	second, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	input := &passwordProbeInput{}
	output := append(append(append(first, '\n'), second...), '\n')
	probe := passwordProbe{input: input, scanner: bufio.NewScanner(bytes.NewReader(output)), user: "trial"}
	before, err := probe.target()
	if err != nil || before.Accessibility || !before.SelectionRequired {
		t.Fatal("private probe lost the AX-disabled authorization target")
	}
	after, err := probe.target()
	if err != nil || before.geometry() == after.geometry() {
		t.Fatal("per-key probe failed to observe a changed authorization panel")
	}
	if input.String() != "{\"action\":\"probe\"}\n{\"action\":\"probe\"}\n" {
		t.Fatal("maintenance probe used a GUI socket command or extra request fields")
	}
}

func TestMaintenancePasswordProbeFallsBackOnlyOnObscuredError(t *testing.T) {
	validTarget := passwordTarget{maintenanceWindow: maintenanceFixture(), SelectionRequired: true}
	validJSON, err := json.Marshal(validTarget)
	if err != nil {
		t.Fatal(err)
	}
	fallbackInput := &passwordProbeInput{}
	fallbackCalled := 0
	probe := passwordProbe{
		input:   &passwordProbeInput{},
		scanner: bufio.NewScanner(bytes.NewReader([]byte("{\"error\":\"setup_password_window_obscured\"}\n"))),
		user:    "trial",
		fallback: func() (*passwordProbe, error) {
			fallbackCalled++
			return &passwordProbe{
				input:   fallbackInput,
				scanner: bufio.NewScanner(bytes.NewReader(append(append(append([]byte{}, validJSON...), '\n'), append(validJSON, '\n')...))),
				user:    "trial",
			}, nil
		},
	}
	got, err := probe.target()
	if err != nil || fallbackCalled != 1 || !got.valid("trial") {
		t.Fatalf("expected fallback to succeed once, err=%v fallbackCalled=%d", err, fallbackCalled)
	}
	got2, err := probe.target()
	if err != nil || fallbackCalled != 1 || !got2.valid("trial") || fallbackInput.String() != "{\"action\":\"probe\"}\n{\"action\":\"probe\"}\n" {
		t.Fatalf("expected subsequent target() to reuse fallback stream, err=%v fallbackCalled=%d", err, fallbackCalled)
	}

	nonObscuredCalled := 0
	nonObscured := passwordProbe{
		input:   &passwordProbeInput{},
		scanner: bufio.NewScanner(bytes.NewReader([]byte("{\"error\":\"setup_password_foreground_changed\"}\n"))),
		user:    "trial",
		fallback: func() (*passwordProbe, error) {
			nonObscuredCalled++
			return nil, nil
		},
	}
	if _, err := nonObscured.target(); err == nil || nonObscuredCalled != 0 {
		t.Fatalf("expected foreground_changed not to trigger compositor fallback, err=%v called=%d", err, nonObscuredCalled)
	}
}
