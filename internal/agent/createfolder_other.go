//go:build !linux

package agent

import "errors"

func createFolderAt(rootDir, rel string, uid, gid int) error {
	return errors.New("creating share folders is only supported on Linux")
}
