package cage

import (
	"strings"
	"testing"
)

func TestGuestServicesConfiguresSSHDLimits(t *testing.T) {
	required := []string{
		"/etc/systemd/system/sshd-vsock.socket.d/20-cage-limits.conf",
		"/etc/systemd/system/sshd-unix-local.socket.d/20-cage-limits.conf",
		"PollLimitIntervalSec=0",
		"PollLimitBurst=0",
		"MaxConnections=512",
		"MaxSessions 128",
	}
	for _, needle := range required {
		if !strings.Contains(guestServices, needle) {
			t.Fatalf("guestServices missing %q", needle)
		}
	}
	socketDropin := strings.Index(guestServices, "20-cage-limits.conf")
	daemonReload := strings.Index(guestServices, "systemctl daemon-reload")
	if socketDropin < 0 || daemonReload < 0 || socketDropin > daemonReload {
		t.Fatalf("expected socket drop-in before daemon-reload (dropin=%d, reload=%d)", socketDropin, daemonReload)
	}
}

func TestBrowserAgentWebGLAndGracefulShutdown(t *testing.T) {
	for _, needle := range []string{
		`"--enable-unsafe-swiftshader"`,
		`process.on("SIGTERM", shutdown)`,
		`process.on("SIGINT", shutdown)`,
		"8000",
	} {
		if !strings.Contains(browserAgent, needle) {
			t.Fatalf("browserAgent missing %q", needle)
		}
	}
	if !strings.Contains(guestServices, "TimeoutStopSec=15") {
		t.Fatal("guestServices missing TimeoutStopSec=15 for cage-browser.service")
	}
}
