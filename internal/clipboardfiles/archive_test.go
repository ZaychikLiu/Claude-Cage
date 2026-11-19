package clipboardfiles

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendFromRootSingleFileAndNestedDirectoryRoundtrip(t *testing.T) {
	project := t.TempDir()
	deckDir := filepath.Join(project, "reports", "interview-20261119", "deck")
	if err := os.MkdirAll(filepath.Join(deckDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	pdfBytes := []byte("%PDF-1.7 sample deck payload")
	noteBytes := []byte("speaker notes")
	if err := os.WriteFile(filepath.Join(deckDir, "deck.pdf"), pdfBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deckDir, "sub", "notes.txt"), noteBytes, 0644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	// Single file extraction
	var fileTar bytes.Buffer
	tw := tar.NewWriter(&fileTar)
	if err := AppendFromRoot(tw, root, filepath.Join("reports", "interview-20261119", "deck", "deck.pdf"), "deck.pdf", map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	extracted, err := read(&fileTar, func() (string, error) { return t.TempDir(), nil })
	if err != nil || len(extracted) != 1 || filepath.Base(extracted[0]) != "deck.pdf" {
		t.Fatalf("single file read: %v %v", extracted, err)
	}
	if got, err := os.ReadFile(extracted[0]); err != nil || !bytes.Equal(got, pdfBytes) {
		t.Fatalf("single file bytes: %v %q", err, got)
	}

	// Whole project directory via relPath="."
	var wholeTar bytes.Buffer
	tw = tar.NewWriter(&wholeTar)
	if err := AppendFromRoot(tw, root, ".", "UMP", map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	extractedDir, err := read(&wholeTar, func() (string, error) { return t.TempDir(), nil })
	if err != nil || len(extractedDir) != 1 || filepath.Base(extractedDir[0]) != "UMP" {
		t.Fatalf("root dir read: %v %v", extractedDir, err)
	}
	if got, err := os.ReadFile(filepath.Join(extractedDir[0], "reports", "interview-20261119", "deck", "deck.pdf")); err != nil || !bytes.Equal(got, pdfBytes) {
		t.Fatalf("nested pdf bytes: %v %q", err, got)
	}
	if got, err := os.ReadFile(filepath.Join(extractedDir[0], "reports", "interview-20261119", "deck", "sub", "notes.txt")); err != nil || !bytes.Equal(got, noteBytes) {
		t.Fatalf("nested note bytes: %v %q", err, got)
	}
}

func TestAppendFromRootRejectsSymlinks(t *testing.T) {
	outside := t.TempDir()
	secretFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	outsideDir := filepath.Join(outside, "dir")
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "inner.txt"), []byte("inner"), 0600); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	if err := os.Symlink(secretFile, filepath.Join(project, "leaf-link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(project, "dir-link")); err != nil {
		t.Fatal(err)
	}
	nestedDir := filepath.Join(project, "nested")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretFile, filepath.Join(nestedDir, "child-link.txt")); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	for _, rel := range []string{
		"leaf-link.txt",
		filepath.Join("dir-link", "inner.txt"),
		"nested",
	} {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		if err := AppendFromRoot(tw, root, rel, filepath.Base(rel), map[string]bool{}); err == nil {
			t.Fatalf("expected symlink rejection for %q", rel)
		}
	}
}

func TestAppendFromRootAndAppendTarStreamCombined(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "proj.txt"), []byte("from-project"), 0644); err != nil {
		t.Fatal(err)
	}
	localDir := t.TempDir()
	localFile := filepath.Join(localDir, "local.txt")
	if err := os.WriteFile(localFile, []byte("from-local"), 0644); err != nil {
		t.Fatal(err)
	}
	dupFile := filepath.Join(localDir, "proj.txt")
	if err := os.WriteFile(dupFile, []byte("duplicate"), 0644); err != nil {
		t.Fatal(err)
	}

	var guestTar bytes.Buffer
	if err := Write(&guestTar, []string{localFile}); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	var combined bytes.Buffer
	tw := tar.NewWriter(&combined)
	names := map[string]bool{}
	if err := AppendFromRoot(tw, root, "proj.txt", "proj.txt", names); err != nil {
		t.Fatal(err)
	}
	if err := AppendTarStream(tw, bytes.NewReader(guestTar.Bytes()), names); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	extracted, err := read(&combined, func() (string, error) { return outDir, nil })
	if err != nil || len(extracted) != 2 {
		t.Fatalf("combined read: %v %v", extracted, err)
	}
	gotProj, _ := os.ReadFile(filepath.Join(outDir, "proj.txt"))
	gotLocal, _ := os.ReadFile(filepath.Join(outDir, "local.txt"))
	if string(gotProj) != "from-project" || string(gotLocal) != "from-local" {
		t.Fatalf("unexpected combined bytes: %q %q", gotProj, gotLocal)
	}

	// Duplicate top-level basename across project and guest stream must fail.
	var dupGuestTar bytes.Buffer
	if err := Write(&dupGuestTar, []string{dupFile}); err != nil {
		t.Fatal(err)
	}
	var dupOut bytes.Buffer
	dupTW := tar.NewWriter(&dupOut)
	dupNames := map[string]bool{}
	if err := AppendFromRoot(dupTW, root, "proj.txt", "proj.txt", dupNames); err != nil {
		t.Fatal(err)
	}
	if err := AppendTarStream(dupTW, bytes.NewReader(dupGuestTar.Bytes()), dupNames); err == nil {
		t.Fatal("expected duplicate top-level basename rejection")
	}
}
