//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/firmdura/triageguard/internal/contracts"
)

type invocation struct {
	code           int
	stdout, stderr []byte
}

func runBinary(t *testing.T, binary string, args ...string) invocation {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("binary hung: %v", args)
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return invocation{code, stdout.Bytes(), stderr.Bytes()}
}

func buildBinary(t *testing.T, repository, target, output string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-ldflags=-X main.version=v0.1.0-test", "-o", output, target)
	cmd.Dir = repository
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", target, err, data)
	}
}

func cliInputs(t *testing.T, repository string) (string, string) {
	t.Helper()
	inputs := t.TempDir()
	fixture := filepath.Join(repository, "testdata/integration")
	if err := filepath.WalkDir(fixture, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(fixture, path)
		if err != nil {
			return err
		}
		if rel == "api" {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(inputs, rel), 0750)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(inputs, rel), data, 0640)
	}); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(inputs, "decisions.yaml"), filepath.Join(inputs, "evidence")
}

func inputSnapshot(t *testing.T, input string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	if err := filepath.WalkDir(input, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(input, path)
		if err != nil {
			return err
		}
		snapshot[rel] = fmt.Sprintf("%x:%v:%v", sha256.Sum256(data), info.Mode(), info.ModTime())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestCLI(t *testing.T) {
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binaries := t.TempDir()
	binary, api := filepath.Join(binaries, "triageguard"), filepath.Join(binaries, "api-consumer")
	buildBinary(t, repository, "./cmd/triageguard", binary)
	buildBinary(t, repository, "./testdata/integration/api", api)

	t.Run("reports-exits-parity-and-inputs", func(t *testing.T) {
		for _, test := range []struct {
			name               string
			change             func(*testing.T, string)
			code               int
			status             contracts.Status
			drift, unavailable int
		}{
			{name: "unchanged", code: 0, status: contracts.StatusUnchanged},
			{name: "changed", change: func(t *testing.T, root string) {
				if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"FEATURE_X":"y","EMPTY":""}`), 0640); err != nil {
					t.Fatal(err)
				}
			}, code: 1, status: contracts.StatusReviewRequired, drift: 1},
			{name: "mixed-unavailable-and-drift", change: func(t *testing.T, root string) {
				if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"FEATURE_X":"y","EMPTY":""}`), 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(root, "source.c")); err != nil {
					t.Fatal(err)
				}
			}, code: 2, status: contracts.StatusUnverifiable, drift: 1, unavailable: 1},
			{name: "malformed-evidence", change: func(t *testing.T, root string) {
				if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"FEATURE_X":"n","FEATURE_X":"n"}`), 0640); err != nil {
					t.Fatal(err)
				}
			}, code: 2, status: contracts.StatusUnverifiable, unavailable: 3},
		} {
			t.Run(test.name, func(t *testing.T) {
				manifest, root := cliInputs(t, repository)
				if test.change != nil {
					test.change(t, root)
				}
				before := inputSnapshot(t, filepath.Dir(manifest))
				args := []string{"check", "--manifest", manifest, "--root", root}
				got := runBinary(t, binary, args...)
				if got.code != test.code || len(got.stderr) != 0 {
					t.Fatalf("code=%d stderr=%s stdout=%s", got.code, got.stderr, got.stdout)
				}
				var report contracts.Report
				decoder := json.NewDecoder(bytes.NewReader(got.stdout))
				if err := decoder.Decode(&report); err != nil {
					t.Fatalf("invalid report: %v\n%s", err, got.stdout)
				}
				if err := decoder.Decode(new(any)); err != io.EOF {
					t.Fatalf("stdout has trailing data: %v", err)
				}
				if report.Status != test.status || report.Summary.Assumptions.ReviewRequired != test.drift || report.Summary.Assumptions.Unverifiable != test.unavailable || len(report.Decisions[0].Assumptions) != 6 {
					t.Fatalf("incorrect complete report: %+v", report)
				}
				apiResult := runBinary(t, api, manifest, root)
				if apiResult.code != 0 || len(apiResult.stderr) != 0 || !bytes.Equal(got.stdout, apiResult.stdout) {
					t.Fatalf("CLI/API differ: CLI=%s API=%+v", got.stdout, apiResult)
				}
				repeated := runBinary(t, binary, append(args, "--format=json")...)
				if repeated.code != got.code || !bytes.Equal(got.stdout, repeated.stdout) || len(repeated.stderr) != 0 {
					t.Fatal("repeated JSON changed")
				}
				markdownArgs := append(args, "--format", "markdown")
				markdown := runBinary(t, binary, markdownArgs...)
				if markdown.code != test.code || len(markdown.stderr) != 0 || !strings.HasPrefix(string(markdown.stdout), "# TriageGuard evidence report\n") {
					t.Fatalf("Markdown invocation failed: %+v", markdown)
				}
				markdownAgain := runBinary(t, binary, markdownArgs...)
				if markdownAgain.code != markdown.code || !bytes.Equal(markdown.stdout, markdownAgain.stdout) {
					t.Fatal("repeated Markdown changed")
				}
				if !reflect.DeepEqual(before, inputSnapshot(t, filepath.Dir(manifest))) {
					t.Fatal("CLI/API changed input hashes/modes/mtime")
				}
			})
		}
	})

	t.Run("root-trailing-slashes", func(t *testing.T) {
		manifest, root := cliInputs(t, repository)
		link := filepath.Join(t.TempDir(), "root-link")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		baseline := runBinary(t, binary, "check", "--manifest", manifest, "--root", root)
		if baseline.code != 0 || len(baseline.stderr) != 0 || len(baseline.stdout) == 0 {
			t.Fatalf("baseline failed: %+v", baseline)
		}
		for _, suffix := range []string{"", "/", "//"} {
			t.Run("symlink"+suffix, func(t *testing.T) {
				got := runBinary(t, binary, "check", "--manifest", manifest, "--root", link+suffix)
				if got.code != 2 || len(got.stdout) != 0 || len(got.stderr) == 0 {
					t.Fatalf("symlink root produced a report: %+v", got)
				}
			})
			t.Run("directory"+suffix, func(t *testing.T) {
				got := runBinary(t, binary, "check", "--manifest", manifest, "--root", root+suffix)
				if got.code != 0 || len(got.stderr) != 0 || !bytes.Equal(got.stdout, baseline.stdout) {
					t.Fatalf("directory root changed report: %+v", got)
				}
			})
		}
	})

	t.Run("help-version-and-strict-errors", func(t *testing.T) {
		manifest, root := cliInputs(t, repository)
		valid := []string{"check", "--manifest", manifest, "--root", root}
		for _, args := range [][]string{{"--help"}, {"-h"}, {"check", "--help"}, {"check", "-h"}, {"--version"}} {
			got := runBinary(t, binary, args...)
			if got.code != 0 || len(got.stderr) != 0 || len(got.stdout) == 0 {
				t.Fatalf("help/version failed: %v %+v", args, got)
			}
			if args[0] == "--version" && string(got.stdout) != "triageguard v0.1.0-test\n" {
				t.Fatalf("version injection failed: %s", got.stdout)
			}
		}
		for _, args := range [][]string{
			nil, {"unknown"}, {"--version", "extra"}, {"check"},
			{"check", "--manifest"}, {"check", "--manifest", "--root", root},
			append(append([]string(nil), valid...), "--format", "xml"),
			append(append([]string(nil), valid...), "--format="),
			append(append([]string(nil), valid...), "--unknown"),
			append(append([]string(nil), valid...), "extra"),
			append(append([]string(nil), valid...), "--root", root),
			{"check", "--manifest=" + manifest, "--root=" + root, "--format", "json", "--format", "json"},
			{"check", "--manifest", filepath.Join(root, "missing"), "--root", root},
			{"check", "--manifest", manifest, "--root", filepath.Join(root, "missing")},
			{"check", "--manifest", manifest, "--root", filepath.Join(root, "source.c")},
			{"check", "--manifest", root, "--root", root},
		} {
			got := runBinary(t, binary, args...)
			if got.code != 2 || len(got.stdout) != 0 || len(got.stderr) == 0 {
				t.Fatalf("expected diagnostic-only exit2: %v %+v", args, got)
			}
		}
		for _, data := range []string{"schema_version: 1\ndecisions: []\n", "schema_version: [", "schema_version: 1\nschema_version: 1\n"} {
			if err := os.WriteFile(manifest, []byte(data), 0640); err != nil {
				t.Fatal(err)
			}
			got := runBinary(t, binary, valid...)
			if got.code != 2 || len(got.stdout) != 0 || len(got.stderr) == 0 {
				t.Fatalf("invalid manifest produced report: %+v", got)
			}
		}
	})

	t.Run("nonregular-manifest-does-not-block", func(t *testing.T) {
		_, root := cliInputs(t, repository)
		fifo := filepath.Join(t.TempDir(), "manifest.fifo")
		if err := syscall.Mkfifo(fifo, 0600); err != nil {
			t.Fatal(err)
		}
		got := runBinary(t, binary, "check", "--manifest", fifo, "--root", root)
		if got.code != 2 || len(got.stdout) != 0 || !strings.Contains(string(got.stderr), "regular file") {
			t.Fatalf("FIFO manifest was not rejected: %+v", got)
		}
	})

	t.Run("broken-output-pipe", func(t *testing.T) {
		manifest, root := cliInputs(t, repository)
		for _, format := range []string{"json", "markdown"} {
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := read.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "check", "--manifest", manifest, "--root", root, "--format", format)
			var stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = write, &stderr
			err = cmd.Run()
			_ = write.Close()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(stderr.String(), "write report") {
				t.Fatalf("broken pipe code/error: %v stderr=%s", err, stderr.String())
			}
		}
	})

	t.Run("signal-cancellation-during-real-hash", func(t *testing.T) {
		root := t.TempDir()
		large := filepath.Join(root, "large.bin")
		file, err := os.Create(large)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(contracts.MaxFileBytes); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(large)
		if err != nil {
			t.Fatal(err)
		}
		manifest := filepath.Join(root, "decisions.yaml")
		data := "schema_version: 1\ndecisions:\n  - id: signal-test\n    cve: CVE-2024-0001\n    baseline: synthetic\n    rationale: Synthetic cancellation test.\n    assumptions:\n      - id: hash\n        kind: file\n        path: large.bin\n        expected_sha256: '" + strings.Repeat("0", 64) + "'\n"
		if err := os.WriteFile(manifest, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
			ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			cmd := exec.CommandContext(ctx, binary, "check", "--manifest", manifest, "--root", root)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Start(); err != nil {
				stop()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			open := false
			for !open {
				entries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", cmd.Process.Pid))
				for _, entry := range entries {
					target, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", cmd.Process.Pid, entry.Name()))
					if target == large {
						open = true
						break
					}
				}
				if open {
					break
				}
				select {
				case err := <-done:
					stop()
					t.Fatalf("process exited before hashing: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
				case <-ctx.Done():
					stop()
					t.Fatal("could not observe real hash handle")
				case <-time.After(time.Millisecond):
				}
			}
			if err := cmd.Process.Signal(sig); err != nil {
				stop()
				t.Fatal(err)
			}
			err := <-done
			stop()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "context canceled") {
				t.Fatalf("signal %v: err=%v stdout=%s stderr=%s", sig, err, stdout.String(), stderr.String())
			}
		}
		after, err := os.Stat(large)
		if err != nil {
			t.Fatal(err)
		}
		if before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
			t.Fatal("cancellation changed evidence metadata")
		}
	})
}

type failingOutput struct{}

func (failingOutput) Write([]byte) (int, error) { return 0, errors.New("output failed") }

type shortOutput struct{}

func (shortOutput) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestCLIHelpOutputFailures(t *testing.T) {
	for _, writer := range []io.Writer{failingOutput{}, shortOutput{}} {
		for _, args := range [][]string{{"--help"}, {"--version"}} {
			var stderr bytes.Buffer
			if code := Run(context.Background(), args, writer, &stderr, "test", Operations{}); code != 2 || !strings.Contains(stderr.String(), "write output") {
				t.Fatalf("output failure lost: code=%d stderr=%s", code, stderr.String())
			}
		}
	}
}
