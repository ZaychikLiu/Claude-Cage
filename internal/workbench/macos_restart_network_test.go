package workbench

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sylvinus/agent-vm/internal/cage"
	"github.com/sylvinus/agent-vm/internal/managedproxy"
	"golang.org/x/crypto/ssh"
)

func TestMacOSLocaleKeepsSecondaryLanguages(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("uses native macOS defaults")
	}
	domain := filepath.Join(t.TempDir(), "regional-preferences")
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("preference operation %s: %v, %s", name, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	apply := func(locale string) { run("/bin/bash", "-c", macOSLocaleScript, "cage-locale", domain, locale) }
	apply("ja_JP")
	if got := run("/usr/bin/defaults", "read", domain, "AppleLocale"); got != "ja_JP" {
		t.Fatalf("new preferences: %q", got)
	}
	run("/usr/bin/defaults", "write", domain, "AppleLanguages", "-array", "fr-FR", "en-US", "ja-JP")
	apply("en_US")
	apply("en_US")
	if got := run("/usr/bin/plutil", "-extract", "AppleLanguages", "json", "-o", "-", domain+".plist"); got != `["en-US","fr-FR","ja-JP"]` {
		t.Fatalf("updated preferences: %q", got)
	}
}

func TestMacOSRegionWaitsForPreferenceAndRuntime(t *testing.T) {
	var applied atomic.Bool
	var samples atomic.Int32
	g := newMacWorkspaceGuest(t, func(ch ssh.Channel, command string) (uint32, bool) {
		if strings.Contains(command, "cage-locale") && strings.Contains(command, "NSGlobalDomain") && strings.Contains(command, "en_US") {
			applied.Store(true)
			return 0, true
		}
		if strings.Contains(command, "result.system_timezone") && applied.Load() {
			zone, language := "America/Los_Angeles", "en-US"
			switch samples.Add(1) {
			case 1:
				zone = "GMT"
			case 2:
				language = "fr-FR"
			}
			fmt.Fprintf(ch, `{"tz":%q,"system_timezone":"America/Los_Angeles","system_locale":"en_US","system_language":%q,"process_locale":"en-US"}`, zone, language)
			return 0, true
		}
		return 1, true
	})
	cfg := cage.DefaultConfig()
	cfg.Timezone = "America/Los_Angeles"
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	if err := g.s.syncMacOSRegion(ctx, cfg); err != nil || samples.Load() != 3 {
		t.Fatalf("startup observations=%d, err=%v", samples.Load(), err)
	}
}

func TestMacOSStartAndControllerReconnectRequireFreshNetworkCheck(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native Mac startup uses the host shell and OpenSSH")
	}
	for _, tc := range []struct {
		name                 string
		start, paused, setup bool
	}{
		{"cold start", true, false, false},
		{"cold start retains pause", true, true, false},
		{"first setup starts offline", true, false, true},
		{"controller adopts running guest", false, false, false},
		{"controller adopts paused guest", false, true, false},
		{"controller adopts unfinished setup", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newMacWorkspaceGuest(t, func(_ ssh.Channel, command string) (uint32, bool) {
				return 0, strings.Contains(command, "uname -s")
			})
			s := g.s
			s.ready = false
			if tc.setup {
				s.macosGuest.SetupID = "awaiting-first-setup"
			}
			if err := writePrivate(filepath.Join(s.profile, "network-intent.json"), networkIntent{Version: 1, Paused: tc.paused, PauseVersion: 7}); err != nil {
				t.Fatal(err)
			}
			if err := s.restoreNetworkIntent(); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfig(s.configPath)
			if err != nil {
				t.Fatal(err)
			}
			gate, err := cage.NewEgressGate(cfg)
			if err != nil {
				t.Fatal(err)
			}
			stop, err := cage.StartGateControl(s.configPath, s.instanceDir(), gate)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			if err = gate.BeginCheck(); err != nil {
				t.Fatal(err)
			}
			grantTestGate(t, gate)
			// Preserve the same configuration fingerprint and old report, but
			// reject the new check before any proxy process or external traffic.
			store, err := managedproxy.Load(s.profile)
			if err != nil {
				t.Fatal(err)
			}
			store.Selected = ""
			if err = store.Save(s.profile); err != nil {
				t.Fatal(err)
			}
			checkFailure := cfg.RequireManagedProxy(s.profile)
			if checkFailure == nil {
				t.Fatal("fixture still has a selected exit")
			}
			wantCheck := !tc.paused && !tc.setup
			if tc.start {
				marker := filepath.Join(s.instanceDir(), "cage-running.json")
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
				s.exe = filepath.Join(t.TempDir(), "cage")
				script := fmt.Sprintf("#!/bin/sh\n[ \"$*\" = 'guest-os macos start' ] || exit 1\nprintf '{\"pid\":%d}' > '%s'\n", os.Getpid(), marker)
				if err := os.WriteFile(s.exe, []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				s.setJobForTest(Job{ID: "starting", Kind: "start", Running: true})
				err := s.startMacOSGuest()
				if wantCheck && (err == nil || err.Error() != checkFailure.Error()) || !wantCheck && err != nil {
					t.Fatalf("start result = %v, want fresh check = %t", err, wantCheck)
				}
			} else {
				s.op.Lock()
				err := s.attachMacOSGuest()
				job := s.jobs.snapshot()
				s.op.Unlock()
				defer s.jobs.close()
				if err != nil {
					t.Fatal(err)
				}
				if (job.Running && job.Kind == "network-recovery") != wantCheck {
					t.Fatalf("controller reconnect job = %+v, want fresh check = %t", job, wantCheck)
				}
				if wantCheck {
					if result := awaitJobIdle(t, &s.jobs); result.Error != checkFailure.Error() {
						t.Fatalf("reconnect completed without the expected proxy check: %+v", result)
					}
				}
			}
			if state := gate.Status(); !s.ready || state.Mode != cage.GateClosed || !time.Now().After(state.Until) || s.networkPaused != tc.paused || s.safety.pauseVersion != 7 {
				t.Fatalf("ready=%t mode=%s paused=%t generation=%d", s.ready, state.Mode, s.networkPaused, s.safety.pauseVersion)
			}
		})
	}
}

func TestMacOSLocaleSyncsBrowserPreferences(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("uses native macOS defaults and osascript")
	}
	root := t.TempDir()
	domain := filepath.Join(root, "regional-preferences")
	profile := filepath.Join(root, "Cage", "Browser")
	runLocale := func(locale, browserLang string) {
		t.Helper()
		out, err := exec.Command("/bin/bash", "-c", macOSLocaleScript, "cage-locale", domain, locale, browserLang, profile).CombinedOutput()
		if err != nil {
			t.Fatalf("macos-locale failed: %v\n%s", err, out)
		}
	}

	// Creates Default/Preferences on a brand-new profile directory.
	runLocale("en_US", "en-US")
	defaultPrefs := filepath.Join(profile, "Default", "Preferences")
	raw, err := os.ReadFile(defaultPrefs)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Intl map[string]any `json:"intl"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Intl["accept_languages"] != "en-US" || parsed.Intl["selected_languages"] != "en-US" {
		t.Fatalf("unexpected default intl: %#v", parsed.Intl)
	}

	// Repairs drifted active profile from Local State without clobbering unrelated keys.
	if err := os.MkdirAll(filepath.Join(profile, "Profile 2"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "Local State"), []byte(`{"profile":{"last_used":"Profile 2"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	p2Prefs := filepath.Join(profile, "Profile 2", "Preferences")
	if err := os.WriteFile(p2Prefs, []byte(`{"intl":{"accept_languages":"en","selected_languages":"en-US,en","extra":"keep"},"unrelated":{"keep":true,"zh":"测试","nil":null}}`), 0600); err != nil {
		t.Fatal(err)
	}
	runLocale("ja_JP", "ja-JP")
	raw, err = os.ReadFile(p2Prefs)
	if err != nil {
		t.Fatal(err)
	}
	var updated struct {
		Intl      map[string]any `json:"intl"`
		Unrelated map[string]any `json:"unrelated"`
	}
	if err := json.Unmarshal(raw, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Intl["accept_languages"] != "ja-JP" || updated.Intl["selected_languages"] != "ja-JP" || updated.Intl["extra"] != "keep" {
		t.Fatalf("unexpected repaired intl: %#v", updated.Intl)
	}
	if updated.Unrelated["keep"] != true || updated.Unrelated["zh"] != "测试" || updated.Unrelated["nil"] != nil {
		t.Fatalf("unrelated keys mutated: %#v", updated.Unrelated)
	}
	if _, exists := updated.Unrelated["nil"]; !exists {
		t.Fatalf("nil key dropped: %s", raw)
	}
	info, err := os.Stat(p2Prefs)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("prefs mode = %o, want 0600", info.Mode().Perm())
	}

	// Idempotent no-op when Preferences already matches.
	beforeMod := info.ModTime()
	time.Sleep(20 * time.Millisecond)
	runLocale("ja_JP", "ja-JP")
	afterInfo, err := os.Stat(p2Prefs)
	if err != nil {
		t.Fatal(err)
	}
	if !afterInfo.ModTime().Equal(beforeMod) {
		t.Fatalf("matching Preferences rewritten unnecessarily: before=%v after=%v", beforeMod, afterInfo.ModTime())
	}
}
