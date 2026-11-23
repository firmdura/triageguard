//go:build linux

package evidence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/firmdura/triageguard/internal/contracts"
)

// New pins root as a Linux directory descriptor. Root setup failures are errors;
// later per-assumption path/read failures are observations. The supplied root
// path is trusted setup input; its final component must not be a symlink. Every
// evidence component is opened relative to pinned descriptors with O_NOFOLLOW.
// Call Close after use. This implementation requires no external dependencies,
// subprocesses, writes, network access, or /proc file descriptor reopening.
func New(root string) (*Collector, error) {
	if root == "" {
		return nil, fmt.Errorf("evidence root must not be empty")
	}
	// A trailing slash makes Linux resolve a symlink before O_NOFOLLOW can
	// reject it. Remove only trailing slashes, preserving the filesystem root
	// and the meaning of trusted parent components such as symlinks or "..".
	path := strings.TrimRight(root, "/")
	if path == "" {
		path = "/"
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open evidence root %q: %w", root, err)
	}
	return &Collector{root: os.NewFile(uintptr(fd), "evidence-root")}, nil
}

func openBeneath(ctx context.Context, root *os.File, name string) (*os.File, contracts.ReasonCode, error) {
	parent := root
	var owned *os.File
	defer func() {
		if owned != nil {
			_ = owned.Close()
		}
	}()
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		// No O_DIRECTORY here: Linux reports a symlink component as ELOOP,
		// rather than conflating it with an ordinary nondirectory component.
		// O_NONBLOCK prevents a substituted FIFO from blocking the open.
		fd, err := syscall.Openat(int(parent.Fd()), part, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, openFailure(err), nil
		}
		f := os.NewFile(uintptr(fd), "evidence")
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, contracts.ReasonEvidenceUnreadable, nil
		}
		if i == len(parts)-1 {
			if !info.Mode().IsRegular() {
				_ = f.Close()
				return nil, contracts.ReasonUnsupportedFileKind, nil
			}
			return f, "", nil
		}
		if !info.IsDir() {
			_ = f.Close()
			return nil, contracts.ReasonUnsupportedFileKind, nil
		}
		if owned != nil {
			_ = owned.Close()
		}
		owned = f
		parent = f
	}
	return nil, contracts.ReasonUnsafePath, nil
}

func openFailure(err error) contracts.ReasonCode {
	switch {
	case errors.Is(err, syscall.ELOOP):
		return contracts.ReasonUnsafePath
	case errors.Is(err, syscall.ENOENT):
		return contracts.ReasonEvidenceMissing
	case errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.ENXIO), errors.Is(err, syscall.ENODEV):
		return contracts.ReasonUnsupportedFileKind
	default:
		return contracts.ReasonEvidenceUnreadable
	}
}
