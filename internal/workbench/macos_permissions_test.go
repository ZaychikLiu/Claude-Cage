package workbench

import (
	"strings"
	"testing"

	"github.com/sylvinus/agent-vm/internal/cage"
)

func TestAssembleMacOSPermissionStatusPassedAndAdHocGuidance(t *testing.T) {
	status := assembleMacOSPermissionStatus(macOSPermissionProbe{
		SetupReady:    true,
		Screen:        true,
		Input:         true,
		Administrator: "cageprovision",
		GuestUser:     "zaychik",
		HelperPaths:   []string{"/Applications/Cage Guest Window.app"},
		Signature:     "adhoc",
		TeamID:        "not set",
		CDHash:        "15b4bc1fb6aaf2f408766c0c0b4c536437521e41",
	})
	if !status.Ready || !status.AdHoc {
		t.Fatalf("expected ready ad-hoc status, got %+v", status)
	}
	if len(status.Checks) != 4 {
		t.Fatalf("expected 4 checks, got %d", len(status.Checks))
	}
	for _, item := range status.Checks {
		if item.State != cage.CheckPassed {
			t.Fatalf("expected passed check %s, got %+v", item.ID, item)
		}
	}
	if !strings.Contains(status.Checks[2].Evidence, "ad-hoc") {
		t.Fatalf("expected ad-hoc note in helper check: %s", status.Checks[2].Evidence)
	}
}

func TestAssembleMacOSPermissionStatusDetectsPitfalls(t *testing.T) {
	status := assembleMacOSPermissionStatus(macOSPermissionProbe{
		SetupReady:                true,
		Screen:                    false,
		Input:                     false,
		EnvironmentUpdateRequired: true,
		Administrator:             "cageprovision",
		GuestUser:                 "zaychik",
		HelperPaths:               []string{"/Applications/Cage Guest Window.app", "/Users/zaychik/Cage Guest Window.app.bak"},
		Signature:                 "adhoc",
		TeamID:                    "not set",
		AutoLoginScreenLocked:     true,
	})
	if status.Ready {
		t.Fatal("expected non-ready status when permissions and checks fail")
	}
	if status.Checks[0].State != cage.CheckFailed || !strings.Contains(status.Checks[0].Remedy, "cageprovision") || !strings.Contains(status.Checks[0].Remedy, "删除旧项") {
		t.Fatalf("expected actionable screen remedy with admin + ad-hoc re-add guidance, got %+v", status.Checks[0])
	}
	if status.Checks[2].State != cage.CheckFailed {
		t.Fatalf("expected helper check failure, got %+v", status.Checks[2])
	}
	if status.Checks[3].State != cage.CheckFailed || !strings.Contains(status.Checks[3].Evidence, "autoLoginUserScreenLocked") {
		t.Fatalf("expected autologin screen lock detection, got %+v", status.Checks[3])
	}
}
