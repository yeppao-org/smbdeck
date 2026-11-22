package validate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Resolve finds the directory that the share path rel designates under
// rootDir, on disk. It refuses anything that leaves the root, and any path
// that goes through a symbolic link at all: a link inside a share could
// otherwise be replaced by someone who can write there, and point another
// share at a folder of the same root it was never meant to expose. The root
// itself may be a link (it is configuration, not data). The resolved
// absolute path is what goes into smb.conf.
//
// Two independent checks must both agree: filepath.EvalSymlinks followed by a
// prefix test, and os.Root, which refuses traversal out of its directory by
// construction.
func Resolve(rootDir, rel string) (string, Code) {
	clean, code := RelPath(rel)
	if code != OK {
		return "", code
	}
	rootReal, err := filepath.EvalSymlinks(rootDir)
	if err != nil {
		return "", ShareRootUnavailable
	}
	if fi, err := os.Stat(rootReal); err != nil || !fi.IsDir() {
		return "", ShareRootUnavailable
	}
	if clean == "" {
		return rootReal, OK
	}

	joined := filepath.Join(rootReal, filepath.FromSlash(clean))
	real, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A dangling link and a missing folder look the same here. If the
			// lexical path exists as a link, say where it goes wrong.
			if _, lerr := os.Lstat(joined); lerr == nil {
				return "", SharePathOutsideRoot
			}
			return "", SharePathMissing
		}
		return "", SharePathInvalid
	}
	if !Within(rootReal, real) {
		return "", SharePathOutsideRoot
	}
	if real != joined {
		return "", SharePathSymlink
	}

	r, err := os.OpenRoot(rootReal)
	if err != nil {
		return "", ShareRootUnavailable
	}
	defer r.Close()
	fi, err := r.Stat(filepath.FromSlash(clean))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", SharePathMissing
		}
		// os.Root reports an escape as a path error: treat every other
		// failure as one.
		return "", SharePathOutsideRoot
	}
	if !fi.IsDir() {
		return "", SharePathNotDirectory
	}

	// The resolved path may differ from the one checked (links inside the
	// root). Every component it adds must pass the same rules.
	inner := strings.TrimPrefix(real, rootReal)
	for _, part := range strings.Split(strings.Trim(inner, "/"), "/") {
		if part != "" && !PathComponent(part) {
			return "", SharePathInvalid
		}
	}
	return real, OK
}

// Within reports whether path is root or inside it. Both must be clean,
// absolute and already resolved.
func Within(root, path string) bool {
	if path == root {
		return true
	}
	if root == "/" {
		return strings.HasPrefix(path, "/")
	}
	return strings.HasPrefix(path, root+"/")
}

// ConfValue reports whether s can be written as a value in smb.conf without
// changing the meaning of the file. smb.conf has no escaping: a value runs to
// the end of the line, a trailing backslash continues it on the next line,
// and a line starting with ';' or '#' is a comment and one starting with '['
// opens a section. Samba also trims spaces and expands %-substitutions.
//
// Every value smbdeck writes passes this check, whatever its origin; the
// generator refuses to write a file otherwise.
func ConfValue(s string) bool {
	if s == "" {
		return true
	}
	if strings.TrimSpace(s) != s {
		return false
	}
	switch s[0] {
	case ';', '#', '[':
		return false
	}
	if strings.HasSuffix(s, `\`) {
		return false
	}
	for _, r := range s {
		switch {
		case r == '%', r == 0:
			return false
		case unicode.IsControl(r), r == '\u2028', r == '\u2029', r == '\u0085', r == '\uFEFF':
			return false
		}
	}
	return true
}

// SectionName reports whether s can be written as an smb.conf section header.
func SectionName(s string) bool {
	return ConfValue(s) && !strings.ContainsAny(s, "[]")
}
