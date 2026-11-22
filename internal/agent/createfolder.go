package agent

import "errors"

// errOwnership: the folder could not be given to the file owner (a file
// system without Unix owners, such as exFAT or NTFS). The folder is removed
// again, so the next pass reports the same error instead of publishing a
// folder with the wrong owner.
var errOwnership = errors.New("cannot set the owner or mode of the new folder")

// createFolder makes rel (and any missing parent) under rootDir. Every
// component is opened relative to its parent's descriptor, refusing symbolic
// links, and the new folder's owner and mode are set on its own descriptor:
// nothing planted between the creation and the change of owner can redirect
// them. New folders belong to the file owner, with the set-group-ID bit like
// "directory mask".
func createFolder(uid, gid int) folderCreator {
	return func(rootDir, rel string) error {
		return createFolderAt(rootDir, rel, uid, gid)
	}
}
