//go:build linux

package agent

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
)

// Indirections for the tests (a file system that refuses chown).
var (
	fchown = syscall.Fchown
	fchmod = syscall.Fchmod
)

func createFolderAt(rootDir, rel string, uid, gid int) error {
	// The root itself may be a link: it is configuration, not data.
	fd, err := syscall.Open(rootDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	done := ""
	for _, part := range strings.Split(rel, "/") {
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if errors.Is(err, syscall.ENOENT) {
			next, err = makeOwnedDir(fd, part, uid, gid)
			if errors.Is(err, errOwnership) {
				// The folder is empty and was just made: remove it, so that
				// the next pass reports the same error instead of publishing
				// it with the wrong owner.
				_ = syscall.Rmdir(filepath.Join(rootDir, done, part))
			}
		}
		_ = syscall.Close(fd)
		if err != nil {
			return err
		}
		fd = next
		done = filepath.Join(done, part)
	}
	return syscall.Close(fd)
}

// makeOwnedDir creates name in the directory dirfd and gives it to uid:gid
// with mode 2775. It returns the new folder's descriptor. On failure after
// the creation, the caller removes the folder.
func makeOwnedDir(dirfd int, name string, uid, gid int) (int, error) {
	// 0700 until it has its owner and mode.
	if err := syscall.Mkdirat(dirfd, name, 0o700); err != nil {
		return -1, err
	}
	fd, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.Join(errOwnership, err)
	}
	// The kernel drops the set-group-ID bit on chmod when the folder's group
	// is not the caller's and the caller lacks CAP_FSETID, which the agent
	// does not have. A folder created under a set-group-ID parent already
	// has the file owner's group: hand it to root's group first (ignored on
	// a file system without owners), set the mode, then give it to the file
	// owner (chown keeps the bit on a directory).
	_ = fchown(fd, 0, 0)
	if err := fchmod(fd, 0o775|syscall.S_ISGID); err != nil {
		_ = syscall.Close(fd)
		return -1, errors.Join(errOwnership, err)
	}
	if err := setOwner(fd, uid, gid); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// setOwner changes the owner of fd. A file system without Unix owners
// refuses; it is accepted only if the folder already shows the wanted owner
// (mount options), otherwise errOwnership.
func setOwner(fd, uid, gid int) error {
	if err := fchown(fd, uid, gid); err != nil {
		var st syscall.Stat_t
		if serr := syscall.Fstat(fd, &st); serr == nil && int(st.Uid) == uid && int(st.Gid) == gid {
			return nil
		}
		return errors.Join(errOwnership, err)
	}
	return nil
}
