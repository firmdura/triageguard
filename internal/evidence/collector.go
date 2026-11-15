// Package evidence collects explicitly declared, read-only filesystem evidence.
// It does not compare expectations, assign decision statuses, or infer CVE
// applicability. Evidence inputs must remain quiescent for an entire run.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/firmdura/triageguard/internal/contracts"
)

// Collector pins one root directory. Concurrent Observe calls are supported;
// Close waits for outstanding observations and prevents later reads. The input
// manifest and evidence must not be changed concurrently by callers.
type Collector struct {
	mu   sync.RWMutex
	root *os.File
}

var _ contracts.Collector = (*Collector)(nil)

// Close releases the pinned root. Repeated calls are safe. It never closes a
// caller-owned file or modifies the evidence directory.
func (c *Collector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.root == nil {
		return nil
	}
	err := c.root.Close()
	c.root = nil
	return err
}

// Observe reads one declared file/key. The expected value/digest is never used
// for comparison here. Per-evidence failures are unavailable observations;
// context cancellation/deadlines are returned as errors with no observation.
// A caller must supply a structurally valid assumption from a validated manifest.
func (c *Collector) Observe(ctx context.Context, a contracts.Assumption) (observation contracts.Observation, err error) {
	defer func() {
		if contextErr := ctx.Err(); contextErr != nil {
			observation, err = contracts.Observation{}, contextErr
		}
	}()
	if err := ctx.Err(); err != nil {
		return contracts.Observation{}, err
	}
	kind, key, _, err := contracts.ExpectationFields(a.Expectation)
	if err != nil {
		return unavailable(contracts.ReasonEvidenceUnreadable), nil
	}
	if !safePath(a.Path) {
		return unavailable(contracts.ReasonUnsafePath), nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.root == nil {
		return unavailable(contracts.ReasonEvidenceUnreadable), nil
	}
	f, reason, err := openBeneath(ctx, c.root, a.Path)
	if err != nil {
		return contracts.Observation{}, err
	}
	if reason != "" {
		return unavailable(reason), nil
	}
	defer f.Close()
	if kind == contracts.KindFile {
		h := sha256.New()
		reason, err := readStable(ctx, f, contracts.MaxFileBytes, func(p []byte) { _, _ = h.Write(p) })
		if err != nil {
			return contracts.Observation{}, err
		}
		if reason != "" {
			return unavailable(reason), nil
		}
		digest := hex.EncodeToString(h.Sum(nil))
		return contracts.Observation{State: contracts.ObservationPresent, SHA256: &digest}, nil
	}
	var data []byte
	reason, err = readStable(ctx, f, contracts.MaxExportBytes, func(p []byte) { data = append(data, p...) })
	if err != nil {
		return contracts.Observation{}, err
	}
	if reason != "" {
		return unavailable(reason), nil
	}
	values, ok := stringMap(data, kind == contracts.KindPatch)
	if !ok {
		return unavailable(contracts.ReasonInvalidExport), nil
	}
	if err := ctx.Err(); err != nil {
		return contracts.Observation{}, err
	}
	value, present := values[*key]
	if !present {
		return contracts.Observation{State: contracts.ObservationAbsent}, nil
	}
	if kind == contracts.KindConfig {
		return contracts.Observation{State: contracts.ObservationPresent, Value: &value}, nil
	}
	return contracts.Observation{State: contracts.ObservationPresent, SHA256: &value}, nil
}

func unavailable(reason contracts.ReasonCode) contracts.Observation {
	return contracts.Observation{State: contracts.ObservationUnavailable, Reason: reason}
}

func safePath(name string) bool {
	return fs.ValidPath(name) && name != "." && !strings.ContainsAny(name, "\\\x00")
}

// readStable consumes one already opened regular file handle, bounded even if
// its size grows. No path is reopened. Size/mtime checks detect observed changes;
// they do not provide a snapshot against a hostile writer restoring metadata.
func readStable(ctx context.Context, f *os.File, max int64, consume func([]byte)) (contracts.ReasonCode, error) {
	before, err := f.Stat()
	if err != nil {
		return contracts.ReasonEvidenceUnreadable, nil
	}
	if !before.Mode().IsRegular() {
		return contracts.ReasonUnsupportedFileKind, nil
	}
	if before.Size() > max {
		return contracts.ReasonLimitExceeded, nil
	}
	buf := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, readErr := f.Read(buf)
		total += int64(n)
		if total > max {
			return contracts.ReasonLimitExceeded, nil
		}
		if n > 0 {
			consume(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			return contracts.ReasonEvidenceUnreadable, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	after, err := f.Stat()
	if err != nil {
		return contracts.ReasonEvidenceUnreadable, nil
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || total != before.Size() {
		return contracts.ReasonEvidenceChanged, nil
	}
	return "", nil
}

// stringMap rejects duplicate keys, lossy Unicode decoding, non-string values,
// extra JSON documents, and (for patch exports) any malformed digest, including
// digests belonging to keys other than the declared one.
func stringMap(data []byte, patch bool) (map[string]string, bool) {
	if !utf8.Valid(data) || !validEscapedUnicode(data) {
		return nil, false
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	values := make(map[string]string)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, false
		}
		key, ok := token.(string)
		if !ok {
			return nil, false
		}
		if _, duplicate := values[key]; duplicate {
			return nil, false
		}
		token, err = d.Token()
		if err != nil {
			return nil, false
		}
		value, ok := token.(string)
		if !ok || (patch && !contracts.ValidSHA256(value)) {
			return nil, false
		}
		values[key] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	return values, true
}

// encoding/json replaces unpaired UTF-16 surrogates; reject them instead of
// turning a supposedly exact exported string into different evidence.
func validEscapedUnicode(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		code, ok := hexQuad(data[i+1 : i+5])
		if !ok {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return false
		}
		low, ok := hexQuad(data[i+3 : i+7])
		if !ok || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

func hexQuad(data []byte) (uint16, bool) {
	var n uint16
	for _, b := range data {
		n <<= 4
		switch {
		case b >= '0' && b <= '9':
			n += uint16(b - '0')
		case b >= 'a' && b <= 'f':
			n += uint16(b - 'a' + 10)
		case b >= 'A' && b <= 'F':
			n += uint16(b - 'A' + 10)
		default:
			return 0, false
		}
	}
	return n, true
}
