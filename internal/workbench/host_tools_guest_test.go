package workbench

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The archive holds the plugin's files, programs still programs, and the
// script on the other side replaces the folder with it.
func TestGuestPluginFilesAreCopiedWhole(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script runs in the environment, which is Linux")
	}
	source := t.TempDir()
	write := func(name, content string, mode os.FileMode) {
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("plugin.json", `{"kind":"guest"}`, 0o644)
	write("sub/plugin.json", "kept: only the plugin's own manifest stays behind", 0o644)
	write("bin/tool", "#!/bin/sh\necho ran\n", 0o755)
	archive, digest, err := packPlugin(source)
	if err != nil || len(digest) != 64 {
		t.Fatalf("pack: %v %q", err, digest)
	}
	if _, again, _ := packPlugin(source); again != digest {
		t.Fatal("the same files gave another digest")
	}
	home := t.TempDir()
	folder := guestPluginRoot + "/sample"
	stale := filepath.Join(home, folder, "old-file")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", guestPluginSyncScript, "sh", folder, digest)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = bytes.NewReader(archive)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("a file of the version before was kept")
	}
	if saved, _ := os.ReadFile(filepath.Join(home, folder, ".digest")); string(saved) != digest {
		t.Fatalf("digest %q", saved)
	}
	if _, err := os.Stat(filepath.Join(home, folder, "plugin.json")); !os.IsNotExist(err) {
		t.Fatal("the manifest was copied into the environment")
	}
	if _, err := os.Stat(filepath.Join(home, folder, "sub", "plugin.json")); err != nil {
		t.Fatal("a file of the plugin was left out")
	}
	if output, err := exec.Command(filepath.Join(home, folder, "bin", "tool")).Output(); err != nil || string(output) != "ran\n" {
		t.Fatalf("the program did not run: %v %q", err, output)
	}
	write("link", "", 0o644)
	if err := os.Remove(filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := packPlugin(source); err == nil {
		t.Fatal("packed a link")
	}
	// The program is found in the folder by its bare name, and one left
	// running from before is ended when the next starts.
	run := func(arguments ...string) *exec.Cmd {
		cmd := exec.Command("sh", append([]string{"-c", guestPluginRunScript, "sh", folder, "0"}, arguments...)...)
		cmd.Env = append(os.Environ(), "HOME="+home)
		return cmd
	}
	if err := os.WriteFile(filepath.Join(home, folder, "tool"), []byte("#!/bin/sh\necho bare \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := run("tool", "a b").Output(); err != nil || string(output) != "bare a b\n" {
		t.Fatalf("bare program: %v %q", err, output)
	}
	// The services' own variables stay with them; an ordinary session's reach
	// the program.
	shown := run("env")
	shown.Env = append(shown.Env, "CAGE_LANGUAGE=en", "BROWSER=/usr/local/bin/opener", "TZ=Europe/London")
	output, err := shown.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"HOME=" + home, "TZ=Europe/London", "npm_config_prefer_offline=true"} {
		if !strings.Contains("\n"+string(output), "\n"+line+"\n") {
			t.Fatalf("%s is missing from the program's environment:\n%s", line, output)
		}
	}
	for _, name := range []string{"CAGE_LANGUAGE=", "BROWSER="} {
		if strings.Contains("\n"+string(output), "\n"+name) {
			t.Fatalf("%s reached the program:\n%s", name, output)
		}
	}
	// Knowing a program by the folder it runs in needs /proc, which the
	// environment has; elsewhere only the rest of the script is checked.
	if runtime.GOOS != "linux" {
		return
	}
	left := run("sleep", "60")
	if err := left.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- left.Wait() }()
	for range 50 {
		if _, err := os.Stat(filepath.Join(home, folder+".pid")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if output, err := run("tool", "next").Output(); err != nil || string(output) != "bare next\n" {
		t.Fatalf("second start: %v %q", err, output)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = left.Process.Kill()
		t.Fatal("the program left from before kept running")
	}
}

func TestRunGuestSSHWithRetry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh -c exit codes")
	}
	exitErr := func(code int) error {
		return exec.Command("sh", "-c", "exit "+string(rune('0'+code))).Run()
	}
	exit255 := func() error {
		return exec.Command("sh", "-c", "exit 255").Run()
	}
	delays := []time.Duration{5 * time.Millisecond, 10 * time.Millisecond}

	t.Run("retries transient exit 255 twice then succeeds", func(t *testing.T) {
		attempts := 0
		out, err := runGuestSSHWithDelays(context.Background(), delays, func() ([]byte, error) {
			attempts++
			if attempts < 3 {
				return []byte("retry"), exit255()
			}
			return []byte("ok"), nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if attempts != 3 || string(out) != "ok" {
			t.Fatalf("got attempts=%d out=%q, want attempts=3 out=ok", attempts, out)
		}
	})

	t.Run("does not retry non-255 exit", func(t *testing.T) {
		attempts := 0
		_, err := runGuestSSHWithDelays(context.Background(), delays, func() ([]byte, error) {
			attempts++
			return nil, exitErr(1)
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if attempts != 1 {
			t.Fatalf("got attempts=%d, want 1", attempts)
		}
	})

	t.Run("aborts promptly on context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		attempts := 0
		start := time.Now()
		_, err := runGuestSSHWithDelays(ctx, []time.Duration{5 * time.Second}, func() ([]byte, error) {
			attempts++
			cancel()
			return nil, exit255()
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got err=%v, want context.Canceled", err)
		}
		if attempts != 1 {
			t.Fatalf("got attempts=%d, want 1", attempts)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("cancellation waited too long: %v", elapsed)
		}
	})
}
