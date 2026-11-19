package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sylvinus/agent-vm/internal/clipboardfiles"
	"github.com/sylvinus/agent-vm/internal/guestos"
)

func TestMacOSClipboardUsesBoundGUIAgent(t *testing.T) {
	s := testServer(t)
	s.macosGuest = &guestos.MacOSProfile{Instance: "mac", User: "guestdev"}
	if err := os.MkdirAll(s.instanceDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.instanceDir(), "ssh.config"), []byte("Host lima-mac\n Port 54432\n User root\n"), 0600); err != nil {
		t.Fatal(err)
	}
	selected := []string{"/tmp/中文 ' $(touch unexpected).txt"}
	for _, operation := range []string{"stream", "import", "export", "request"} {
		cmd, source, err := s.clipboardCommand(context.Background(), operation, clipboardFileSelection{Paths: selected, User: "guest"})
		if err != nil || cmd.Err != nil || source != "guest" {
			t.Fatalf("%s transport: %v", operation, err)
		}
		command := cmd.Args[len(cmd.Args)-1]
		if command != "exec '/Applications/Cage Guest Clipboard.app/Contents/MacOS/CageGuestClipboard' --client "+operation ||
			!slices.Contains(cmd.Args, "guestdev") || slices.Contains(cmd.Args, "root") || strings.Contains(command, selected[0]) {
			t.Fatalf("%s escaped its fixed guest transport", operation)
		}
		if operation == "export" {
			data, _ := io.ReadAll(cmd.Stdin)
			var actual []string
			if json.Unmarshal(data, &actual) != nil || !slices.Equal(actual, selected) {
				t.Fatal("file selections did not travel as stdin JSON")
			}
		}
	}
	for _, item := range []struct{ operation, user string }{{"execute", "guest"}, {"export", "root"}, {"export", "cage-browser"}} {
		if _, _, err := s.clipboardCommand(context.Background(), item.operation, clipboardFileSelection{User: item.user}); err == nil {
			t.Fatalf("accepted %s for %s", item.operation, item.user)
		}
	}
}

func setupMacOSClipboardTestServer(t *testing.T, share *projectShare) (*Server, string, string, *httptest.Server, http.Header) {
	t.Helper()
	projectDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := testServer(t)
	s.macosGuest = &guestos.MacOSProfile{Instance: "mac", User: "guestdev"}
	s.preferences.Workspace = projectDir
	s.ready = true
	if err := writePrivate(filepath.Join(s.profile, "projects.json"), sharedProjects{Paths: []string{projectDir}}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.instanceDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.instanceDir(), "cage-running.json"), []byte(fmt.Sprintf(`{"pid":%d}`, os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if share != nil {
		s.projectShares = map[string]*projectShare{projectDir: share}
	}
	// Point PATH to an empty directory so any accidental SSH invocation fails immediately.
	t.Setenv("PATH", t.TempDir())

	server := httptest.NewServer(s.handler())
	t.Cleanup(server.Close)
	s.origin = server.URL
	headers := http.Header{
		"Origin": {s.origin},
		"Cookie": {s.cookieName() + "=" + s.session + "; " + s.cookieName() + "-desktop=" + trustedViewProof(s.token)},
	}
	guestRoot := macOSProjectPath(s.macosGuest.User, projectDir)
	return s, projectDir, guestRoot, server, headers
}

func TestMacOSClipboardExportsApprovedProjectFilesWithoutSSH(t *testing.T) {
	done := make(chan struct{})
	s, projectDir, guestRoot, server, headers := setupMacOSClipboardTestServer(t, &projectShare{done: done})

	deckRel := filepath.Join("reports", "interview-20261119", "deck", "deck.pdf")
	deckPath := filepath.Join(projectDir, deckRel)
	if err := os.MkdirAll(filepath.Dir(deckPath), 0755); err != nil {
		t.Fatal(err)
	}
	pdfBytes := []byte("%PDF-1.7 test deck bytes\n")
	notesBytes := []byte("notes markdown\n")
	if err := os.WriteFile(deckPath, pdfBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "reports", "notes.md"), notesBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// Single file from approved active share.
	id := s.registerClipboardFiles([]string{guestRoot + "/reports/interview-20261119/deck/deck.pdf"}, "guest")
	req, _ := http.NewRequest("GET", s.origin+"/api/clipboard/files/"+id, nil)
	req.Header = headers.Clone()
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cache := clipboardfiles.CacheStore{Directory: t.TempDir()}
	selection, recvErr := receiveClipboardArchive(resp, cache)
	resp.Body.Close()
	if resp.StatusCode != 200 || recvErr != nil || resp.Trailer.Get("X-Cage-Clipboard-Status") != "ok" {
		t.Fatalf("single project file export failed: status=%d trailer=%q err=%v", resp.StatusCode, resp.Trailer.Get("X-Cage-Clipboard-Status"), recvErr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(selection.Paths[0])) })
	if len(selection.Paths) != 1 || filepath.Base(selection.Paths[0]) != "deck.pdf" {
		t.Fatalf("unexpected extracted paths: %v", selection.Paths)
	}
	gotPDF, err := os.ReadFile(selection.Paths[0])
	if err != nil || !bytes.Equal(gotPDF, pdfBytes) {
		t.Fatalf("pdf content mismatch: err=%v bytes=%q", err, gotPDF)
	}

	// Nested directory from approved active share.
	dirID := s.registerClipboardFiles([]string{guestRoot + "/reports"}, "guest")
	req, _ = http.NewRequest("GET", s.origin+"/api/clipboard/files/"+dirID, nil)
	req.Header = headers.Clone()
	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	dirCache := clipboardfiles.CacheStore{Directory: t.TempDir()}
	dirSel, recvErr := receiveClipboardArchive(resp, dirCache)
	resp.Body.Close()
	if resp.StatusCode != 200 || recvErr != nil || resp.Trailer.Get("X-Cage-Clipboard-Status") != "ok" {
		t.Fatalf("directory export failed: status=%d trailer=%q err=%v", resp.StatusCode, resp.Trailer.Get("X-Cage-Clipboard-Status"), recvErr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(dirSel.Paths[0])) })
	gotNotes, err := os.ReadFile(filepath.Join(dirSel.Paths[0], "notes.md"))
	if err != nil || !bytes.Equal(gotNotes, notesBytes) {
		t.Fatalf("nested directory notes mismatch: err=%v bytes=%q", err, gotNotes)
	}
	gotNestedPDF, err := os.ReadFile(filepath.Join(dirSel.Paths[0], "interview-20261119", "deck", "deck.pdf"))
	if err != nil || !bytes.Equal(gotNestedPDF, pdfBytes) {
		t.Fatalf("nested pdf mismatch: err=%v bytes=%q", err, gotNestedPDF)
	}
}

func TestMacOSClipboardRejectsUnapprovedOrSymlinkedProjectSelections(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}

	fetch := func(t *testing.T, s *Server, server *httptest.Server, headers http.Header, guestPath string) (int, error) {
		t.Helper()
		id := s.registerClipboardFiles([]string{guestPath}, "guest")
		req, _ := http.NewRequest("GET", s.origin+"/api/clipboard/files/"+id, nil)
		req.Header = headers.Clone()
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, fmt.Errorf("http %d", resp.StatusCode)
		}
		_, recvErr := receiveClipboardArchive(resp, clipboardfiles.CacheStore{Directory: t.TempDir()})
		return resp.StatusCode, recvErr
	}

	assertRejected := func(t *testing.T, status int, err error) {
		t.Helper()
		if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusLocked {
			t.Fatalf("expected request to pass auth middleware, got %d", status)
		}
		if status == http.StatusOK && err == nil {
			t.Fatal("expected invalid project selection to fail")
		}
	}

	t.Run("unshared project", func(t *testing.T) {
		s, _, _, server, headers := setupMacOSClipboardTestServer(t, &projectShare{done: make(chan struct{})})
		status, err := fetch(t, s, server, headers, "/Users/guestdev/Cage/Projects/0123456789abcdef01234567/file.txt")
		assertRejected(t, status, err)
	})

	t.Run("pending approval share", func(t *testing.T) {
		s, projectDir, guestRoot, server, headers := setupMacOSClipboardTestServer(t, &projectShare{done: make(chan struct{}), approval: "pending"})
		if err := os.WriteFile(filepath.Join(projectDir, "a.txt"), []byte("a"), 0644); err != nil {
			t.Fatal(err)
		}
		status, err := fetch(t, s, server, headers, guestRoot+"/a.txt")
		assertRejected(t, status, err)
	})

	t.Run("closed share", func(t *testing.T) {
		done := make(chan struct{})
		close(done)
		s, projectDir, guestRoot, server, headers := setupMacOSClipboardTestServer(t, &projectShare{done: done})
		if err := os.WriteFile(filepath.Join(projectDir, "a.txt"), []byte("a"), 0644); err != nil {
			t.Fatal(err)
		}
		status, err := fetch(t, s, server, headers, guestRoot+"/a.txt")
		assertRejected(t, status, err)
	})

	t.Run("symlink escaping project", func(t *testing.T) {
		s, projectDir, guestRoot, server, headers := setupMacOSClipboardTestServer(t, &projectShare{done: make(chan struct{})})
		if err := os.Symlink(secret, filepath.Join(projectDir, "escape.txt")); err != nil {
			t.Fatal(err)
		}
		status, err := fetch(t, s, server, headers, guestRoot+"/escape.txt")
		assertRejected(t, status, err)
	})
}
