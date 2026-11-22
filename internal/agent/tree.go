package agent

import (
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/yeppao-org/smbdeck/internal/state"
	"github.com/yeppao-org/smbdeck/internal/validate"
)

// Limits of the folder tree published for the web console's folder picker.
const (
	treeDepth      = 2
	treeMaxFolders = 2000
	// treeBatch is how many directory entries are read at a time: a folder
	// with a million files is never loaded at once.
	treeBatch = 256
)

// scanTree lists the folders of each root, two levels deep, breadth first:
// every top-level folder is listed before any subfolder, so a crowded folder
// cannot push the others out. It does not follow symbolic links, skips
// hidden folders, and leaves out any name that could not pass validation
// (the picker only offers paths the agent would accept).
func scanTree(roots []Root, now time.Time) state.Tree {
	t := state.Tree{GeneratedAt: now.UTC(), Roots: []state.TreeRoot{}}
	for _, r := range roots {
		tr := state.TreeRoot{Name: r.Name, Folders: []string{}}
		root, err := os.OpenRoot(r.Dir)
		if err == nil {
			tr.Available = true
			tr.Folders, tr.Truncated = listFolders(root)
			_ = root.Close()
		}
		t.Roots = append(t.Roots, tr)
	}
	return t
}

func listFolders(root *os.Root) ([]string, bool) {
	type item struct {
		path  string
		depth int
	}
	folders := []string{}
	queue := []item{{".", 0}}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		f, err := root.Open(it.path)
		if err != nil {
			continue
		}
		for {
			entries, err := f.ReadDir(treeBatch)
			for _, e := range entries {
				// DirEntry.IsDir is false for a symbolic link: links are not offered.
				if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || !validate.PathComponent(e.Name()) {
					continue
				}
				if len(folders) >= treeMaxFolders {
					_ = f.Close()
					slices.Sort(folders)
					return folders, true
				}
				p := e.Name()
				if it.path != "." {
					p = path.Join(it.path, e.Name())
				}
				folders = append(folders, p)
				if it.depth+1 < treeDepth {
					queue = append(queue, item{p, it.depth + 1})
				}
			}
			if err != nil || len(entries) == 0 {
				break
			}
		}
		_ = f.Close()
	}
	slices.Sort(folders)
	return folders, false
}
