//go:build linux

package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/firmdura/triageguard/internal/contracts"
)

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	entries, err := os.ReadDir("../../testdata/evidence")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "README.md" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("../../testdata/evidence", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, entry.Name()), data, 0640); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func collector(t *testing.T, root string) *Collector {
	t.Helper()
	c, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

func assumption(path string, e contracts.Expectation) contracts.Assumption {
	return contracts.Assumption{ID: "synthetic", Path: path, Expectation: e}
}

func observe(t *testing.T, c *Collector, path string, e contracts.Expectation) contracts.Observation {
	t.Helper()
	o, err := c.Observe(context.Background(), assumption(path, e))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func TestEvidenceValidObservationsAndInputImmutability(t *testing.T) {
	root := fixtureRoot(t)
	if err := os.Mkdir(filepath.Join(root, "nested"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "data"), []byte("nested evidence\n"), 0400); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, root)
	c := collector(t, root)
	for _, test := range []struct {
		name, path string
		e          contracts.Expectation
		want       contracts.Observation
	}{
		{"config", "config.json", &contracts.ConfigPresent{Key: "FEATURE_X", Value: "not-used"}, contracts.Observation{State: contracts.ObservationPresent, Value: ptr("n")}},
		{"expected-absent-but-present", "config.json", &contracts.ConfigAbsent{Key: "FEATURE_X"}, contracts.Observation{State: contracts.ObservationPresent, Value: ptr("n")}},
		{"empty", "config.json", &contracts.ConfigPresent{Key: "EMPTY", Value: "ignored"}, contracts.Observation{State: contracts.ObservationPresent, Value: ptr("")}},
		{"empty-key", "config.json", &contracts.ConfigAbsent{Key: ""}, contracts.Observation{State: contracts.ObservationPresent, Value: ptr("empty-key")}},
		{"unicode", "config.json", &contracts.ConfigAbsent{Key: "unicode"}, contracts.Observation{State: contracts.ObservationPresent, Value: ptr("snowman ☃")}},
		{"absent", "config.json", &contracts.ConfigPresent{Key: "NOT_EXPORTED", Value: ""}, contracts.Observation{State: contracts.ObservationAbsent}},
		{"patch", "patches.json", &contracts.PatchPresent{Key: "fix-1", SHA256: strings.Repeat("0", 64)}, contracts.Observation{State: contracts.ObservationPresent, SHA256: ptr(digest([]byte("synthetic patch bytes\n")))}},
		{"patch-absent", "patches.json", &contracts.PatchAbsent{Key: "missing"}, contracts.Observation{State: contracts.ObservationAbsent}},
		{"nested-file", "nested/data", &contracts.FileSHA256{SHA256: strings.Repeat("0", 64)}, contracts.Observation{State: contracts.ObservationPresent, SHA256: ptr(digest([]byte("nested evidence\n")))}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := observe(t, c, test.path, test.e); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %#v, want %#v", got, test.want)
			}
		})
	}
	data, err := os.ReadFile(filepath.Join(root, "source.c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{digest(data), strings.Repeat("0", 64)} {
		o := observe(t, c, "source.c", &contracts.FileSHA256{SHA256: expected})
		if o.State != contracts.ObservationPresent || o.SHA256 == nil || *o.SHA256 != digest(data) || o.Reason != "" {
			t.Fatalf("hash observation compared expected value: %#v", o)
		}
	}
	if after := snapshot(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("collector modified input bytes, modes, sizes or mtimes")
	}
}

func ptr(s string) *string { return &s }

type fileSnapshot struct {
	Mode  fs.FileMode
	Size  int64
	Mtime time.Time
	Hash  string
}

func snapshot(t *testing.T, root string) map[string]fileSnapshot {
	t.Helper()
	out := make(map[string]fileSnapshot)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		s := fileSnapshot{Mode: info.Mode(), Size: info.Size(), Mtime: info.ModTime()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			s.Hash = digest(data)
		}
		out[rel] = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEvidenceMalformedExports(t *testing.T) {
	c := collector(t, fixtureRoot(t))
	for _, path := range []string{"duplicate.json", "duplicate-escaped.json", "malformed.json", "nonstring.json", "null.json", "array.json", "nested.json", "trailing.json", "bad-utf8.json", "unpaired-high.json", "unpaired-low.json"} {
		t.Run(path, func(t *testing.T) {
			wantUnavailable(t, observe(t, c, path, &contracts.ConfigAbsent{Key: "FEATURE_X"}), contracts.ReasonInvalidExport)
		})
	}
	for _, path := range []string{"patch-bad-hash.json", "patch-bad-unrelated.json"} {
		wantUnavailable(t, observe(t, c, path, &contracts.PatchAbsent{Key: "fix-1"}), contracts.ReasonInvalidExport)
	}
	for _, data := range []string{`{"x":1}`, `{"x":null}`, `{"x":[]}`, `{"x":"n",}`, `{"x":"n"}true`, `{"x":"\uD800x"}`, `{"x":"\uD800\u0000"}`, `{"x":"\uZZZZ"}`} {
		if _, ok := stringMap([]byte(data), false); ok {
			t.Fatalf("accepted malformed export %q", data)
		}
	}
	for _, data := range []string{`{}`, `{"x":"\uD83D\uDE00"}`, `{"x":"\\ud800"}`, `{"x":"escaped \" quote"}`} {
		if _, ok := stringMap([]byte(data), false); !ok {
			t.Fatalf("rejected valid exact string export %q", data)
		}
	}
}

func wantUnavailable(t *testing.T, o contracts.Observation, reason contracts.ReasonCode) {
	t.Helper()
	if !reflect.DeepEqual(o, contracts.Observation{State: contracts.ObservationUnavailable, Reason: reason}) {
		t.Fatalf("got %#v; want unavailable/%s", o, reason)
	}
}

func TestEvidencePathsAndFileKinds(t *testing.T) {
	root := fixtureRoot(t)
	c := collector(t, root)
	e := &contracts.ConfigAbsent{Key: "FEATURE_X"}
	for _, path := range []string{"", ".", "..", "../config.json", "/etc/passwd", "a/../config.json", "a/./b", "a//b", "a/", "a\\b", "a\x00b", string([]byte{0xff})} {
		wantUnavailable(t, observe(t, c, path, e), contracts.ReasonUnsafePath)
	}
	wantUnavailable(t, observe(t, c, "missing.json", e), contracts.ReasonEvidenceMissing)
	wantUnavailable(t, observe(t, c, "missing/child", e), contracts.ReasonEvidenceMissing)
	wantUnavailable(t, observe(t, c, "source.c/child", e), contracts.ReasonUnsupportedFileKind)
	if err := os.Mkdir(filepath.Join(root, "directory"), 0755); err != nil {
		t.Fatal(err)
	}
	wantUnavailable(t, observe(t, c, "directory", e), contracts.ReasonUnsupportedFileKind)
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	wantUnavailable(t, observe(t, c, "fifo", e), contracts.ReasonUnsupportedFileKind)
	wantUnavailable(t, observe(t, c, "fifo/child", e), contracts.ReasonUnsupportedFileKind)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"internal-leaf": "config.json", "escape-leaf": filepath.Join(outside, "secret"), "internal-dir": "directory", "escape-dir": outside, "dangling": "missing"} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
		path := name
		if strings.HasSuffix(name, "dir") {
			path += "/child"
		}
		wantUnavailable(t, observe(t, c, path, e), contracts.ReasonUnsafePath)
	}
}

func TestEvidenceRootPinAndLifecycle(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"x":"original"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := collector(t, root)
	if err := os.Rename(root, filepath.Join(parent, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"x":"replacement"}`), 0600); err != nil {
		t.Fatal(err)
	}
	o := observe(t, c, "config.json", &contracts.ConfigAbsent{Key: "x"})
	if o.Value == nil || *o.Value != "original" {
		t.Fatalf("root pathname was reopened: %#v", o)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, err := c.Observe(context.Background(), assumption("config.json", &contracts.ConfigAbsent{Key: "x"}))
			if err != nil || o.Value == nil || *o.Value != "original" {
				t.Errorf("concurrent observation: %#v %v", o, err)
			}
		}()
	}
	wg.Wait()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	wantUnavailable(t, observe(t, c, "config.json", &contracts.ConfigAbsent{Key: "x"}), contracts.ReasonEvidenceUnreadable)
	for _, path := range []string{"", filepath.Join(parent, "missing"), filepath.Join(root, "config.json")} {
		if c, err := New(path); err == nil {
			_ = c.Close()
			t.Fatalf("invalid root accepted: %q", path)
		}
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if c, err := New(link); err == nil {
		_ = c.Close()
		t.Fatal("symlink root accepted")
	}
}

func TestEvidenceRootTrailingSlashes(t *testing.T) {
	root := fixtureRoot(t)
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(filepath.Dir(root), parentLink); err != nil {
		t.Fatal(err)
	}
	trustedParentRoot := filepath.Join(parentLink, filepath.Base(root))
	for _, suffix := range []string{"", "/", "//"} {
		t.Run("symlink"+suffix, func(t *testing.T) {
			c, err := New(link + suffix)
			if err == nil {
				_ = c.Close()
				t.Fatal("symlink root accepted")
			}
			if c != nil {
				t.Fatal("root setup error returned a collector")
			}
		})
		t.Run("directory"+suffix, func(t *testing.T) {
			c := collector(t, root+suffix)
			o := observe(t, c, "config.json", &contracts.ConfigPresent{Key: "FEATURE_X", Value: "n"})
			if o.State != contracts.ObservationPresent || o.Value == nil || *o.Value != "n" {
				t.Fatalf("directory root did not provide evidence: %#v", o)
			}
		})
		t.Run("trusted-parent"+suffix, func(t *testing.T) {
			c := collector(t, trustedParentRoot+suffix)
			o := observe(t, c, "config.json", &contracts.ConfigPresent{Key: "FEATURE_X", Value: "n"})
			if o.State != contracts.ObservationPresent || o.Value == nil || *o.Value != "n" {
				t.Fatalf("trusted parent root did not provide evidence: %#v", o)
			}
		})
	}
	for _, path := range []string{"/", "//", "///"} {
		t.Run("filesystem-root"+path, func(t *testing.T) {
			collector(t, path)
		})
	}
}

func TestEvidenceLimits(t *testing.T) {
	root := t.TempDir()
	c := collector(t, root)
	for _, test := range []struct {
		name string
		size int64
		e    contracts.Expectation
	}{{"file", contracts.MaxFileBytes + 1, &contracts.FileSHA256{SHA256: strings.Repeat("0", 64)}}, {"config", contracts.MaxExportBytes + 1, &contracts.ConfigAbsent{Key: "x"}}, {"patch", contracts.MaxExportBytes + 1, &contracts.PatchAbsent{Key: "x"}}} {
		f, err := os.Create(filepath.Join(root, test.name))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(test.size); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		wantUnavailable(t, observe(t, c, test.name, test.e), contracts.ReasonLimitExceeded)
	}
	value := strings.Repeat("x", int(contracts.MaxExportBytes)-len(`{"x":""}`))
	if err := os.WriteFile(filepath.Join(root, "exact.json"), []byte(`{"x":"`+value+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	o := observe(t, c, "exact.json", &contracts.ConfigAbsent{Key: "x"})
	if o.State != contracts.ObservationPresent || o.Value == nil || len(*o.Value) != len(value) {
		t.Fatalf("exact export limit rejected: %s/%s", o.State, o.Reason)
	}
}

func TestEvidenceCancellationAndObservedMutation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "source")
	data := []byte(strings.Repeat("x", 256<<10))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := collector(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if o, err := c.Observe(ctx, assumption("source", &contracts.FileSHA256{SHA256: strings.Repeat("0", 64)})); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(o, contracts.Observation{}) {
		t.Fatalf("cancellation lost: %#v %v", o, err)
	}
	for _, mutation := range []string{"cancel", "size", "mtime", "growth-limit"} {
		t.Run(mutation, func(t *testing.T) {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			changed := false
			limit := contracts.MaxFileBytes
			if mutation == "growth-limit" {
				limit = int64(len(data))
			}
			reason, err := readStable(ctx, f, limit, func([]byte) {
				if changed {
					return
				}
				changed = true
				switch mutation {
				case "cancel":
					cancel()
				case "size", "growth-limit":
					w, e := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
					if e != nil {
						t.Fatal(e)
					}
					_, e = w.Write([]byte("changed"))
					_ = w.Close()
					if e != nil {
						t.Fatal(e)
					}
				case "mtime":
					future := time.Now().Add(time.Hour)
					if e := os.Chtimes(path, future, future); e != nil {
						t.Fatal(e)
					}
				}
			})
			if !changed {
				t.Fatal("test did not mutate/cancel during the read")
			}
			if mutation == "cancel" {
				if !errors.Is(err, context.Canceled) || reason != "" {
					t.Fatalf("hash cancellation: %s %v", reason, err)
				}
				return
			}
			want := contracts.ReasonEvidenceChanged
			if mutation == "growth-limit" {
				want = contracts.ReasonLimitExceeded
			}
			if err != nil || reason != want {
				t.Fatalf("mutation %s: %s %v", mutation, reason, err)
			}
		})
	}
}

func TestEvidenceDeniedRead(t *testing.T) {
	root, err := os.MkdirTemp("", "triageguard-denied-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "denied")
	if err := os.WriteFile(path, []byte("private evidence"), 0000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		// The helper drops privileges and verifies an actual EACCES. Copy the
		// test binary out of Go's potentially private build directory first.
		binary, err := os.ReadFile(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		helper := filepath.Join(root, "permission-test")
		if err := os.WriteFile(helper, binary, 0755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(helper, "-test.run=^TestEvidenceDeniedReadHelper$", "-test.v")
		cmd.Env = append(os.Environ(), "TRIAGEGUARD_DENIED_ROOT="+root)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("unprivileged permission helper: %v\n%s", err, out)
		}
	} else {
		assertDeniedRead(t, root)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0 {
		t.Fatalf("denied file mode changed: %v", err)
	}
}

func TestEvidenceDeniedReadHelper(t *testing.T) {
	root := os.Getenv("TRIAGEGUARD_DENIED_ROOT")
	if root == "" {
		return
	}
	if os.Geteuid() == 0 {
		t.Fatal("permission helper still root")
	}
	assertDeniedRead(t, root)
}

func assertDeniedRead(t *testing.T, root string) {
	t.Helper()
	f, err := os.Open(filepath.Join(root, "denied"))
	if err == nil {
		_ = f.Close()
		t.Fatal("permission test did not deny a real read")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("expected EACCES, got %v", err)
	}
	c := collector(t, root)
	wantUnavailable(t, observe(t, c, "denied", &contracts.ConfigAbsent{Key: "x"}), contracts.ReasonEvidenceUnreadable)
}

func TestEvidenceComponentSubstitutionStaysConfined(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	slot := filepath.Join(root, "slot")
	parked := filepath.Join(root, "parked")
	if err := os.Mkdir(slot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "config.json"), []byte(`{"x":"inside"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "config.json"), []byte(`{"x":"OUTSIDE-SECRET"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := collector(t, root)
	substituted := make(chan struct{})
	resume := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan struct{})
	var mutationErr error
	var attempts atomic.Int64
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := os.Rename(slot, parked); err != nil {
				mutationErr = err
				return
			}
			if err := os.Symlink(outside, slot); err != nil {
				mutationErr = err
				return
			}
			attempts.Add(1)
			select {
			case substituted <- struct{}{}:
			case <-stop:
				return
			}
			select {
			case <-resume:
			case <-stop:
				return
			}
			runtime.Gosched()
			if err := os.Remove(slot); err != nil {
				mutationErr = err
				return
			}
			if err := os.Rename(parked, slot); err != nil {
				mutationErr = err
				return
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
		if mutationErr != nil {
			t.Error(mutationErr)
		}
	}()
	const rounds, probesPerRound = 30, 50
	for round := 0; round < rounds; round++ {
		// A handshake for every round guarantees repeated real substitutions,
		// even when the probe goroutine otherwise outruns the mutator.
		select {
		case <-substituted:
		case <-done:
			t.Fatalf("component mutator stopped: %v", mutationErr)
		}
		wantUnavailable(t, observe(t, c, "slot/config.json", &contracts.ConfigAbsent{Key: "x"}), contracts.ReasonUnsafePath)
		resume <- struct{}{}
		for probe := 0; probe < probesPerRound; probe++ {
			runtime.Gosched()
			o := observe(t, c, "slot/config.json", &contracts.ConfigAbsent{Key: "x"})
			if o.State == contracts.ObservationPresent {
				if o.Value == nil || *o.Value != "inside" {
					t.Fatalf("component substitution escaped root: %#v", o)
				}
			} else if o.State != contracts.ObservationUnavailable || (o.Reason != contracts.ReasonUnsafePath && o.Reason != contracts.ReasonEvidenceMissing) {
				t.Fatalf("unexpected substitution result: %#v", o)
			}
		}
	}
	if attempts.Load() < rounds {
		t.Fatalf("incomplete component substitutions: %d", attempts.Load())
	}
}
