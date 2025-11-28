package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileTreeNode represents a node in the file tree.
type FileTreeNode struct {
	Name     string
	Path     string
	IsDir    bool
	Children []*FileTreeNode
	Expanded bool
	Depth    int
}

// FileTree represents a file tree view.
type FileTree struct {
	Root     *FileTreeNode
	Selected int
	Nodes    []*FileTreeNode // Flattened visible nodes
}

// NewFileTree creates a file tree from a root path.
func NewFileTree(rootPath string, maxDepth int) (*FileTree, error) {
	info, err := os.Stat(rootPath)
	if err != nil {
		return nil, err
	}
	
	root := &FileTreeNode{
		Name:     filepath.Base(rootPath),
		Path:     rootPath,
		IsDir:    info.IsDir(),
		Expanded: true,
		Depth:    0,
	}
	
	if root.IsDir {
		buildTree(root, maxDepth)
	}
	
	ft := &FileTree{Root: root}
	ft.flatten()
	
	return ft, nil
}

// buildTree recursively builds the tree.
func buildTree(node *FileTreeNode, maxDepth int) {
	if node.Depth >= maxDepth {
		return
	}
	
	entries, err := os.ReadDir(node.Path)
	if err != nil {
		return
	}
	
	// Sort: directories first, then alphabetically
	sort.Slice(entries, func(i, j int) bool {
		iDir := entries[i].IsDir()
		jDir := entries[j].IsDir()
		if iDir != jDir {
			return iDir
		}
		return entries[i].Name() < entries[j].Name()
	})
	
	for _, entry := range entries {
		// Skip hidden files and common uninteresting directories
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if isSkippedDir(name) {
			continue
		}
		
		child := &FileTreeNode{
			Name:  name,
			Path:  filepath.Join(node.Path, name),
			IsDir: entry.IsDir(),
			Depth: node.Depth + 1,
		}
		
		if child.IsDir && child.Depth < maxDepth {
			buildTree(child, maxDepth)
		}
		
		node.Children = append(node.Children, child)
	}
}

// isSkippedDir returns true for directories we don't want to show.
func isSkippedDir(name string) bool {
	skip := map[string]bool{
		"node_modules": true,
		"__pycache__":  true,
		"venv":         true,
		".git":         true,
		".svn":         true,
		"vendor":       true,
		"dist":         true,
		"build":        true,
	}
	return skip[name]
}

// flatten creates a flat list of visible nodes.
func (ft *FileTree) flatten() {
	ft.Nodes = nil
	ft.flattenNode(ft.Root)
}

func (ft *FileTree) flattenNode(node *FileTreeNode) {
	ft.Nodes = append(ft.Nodes, node)
	
	if node.IsDir && node.Expanded {
		for _, child := range node.Children {
			ft.flattenNode(child)
		}
	}
}

// Toggle expands/collapses the selected node.
func (ft *FileTree) Toggle() {
	if ft.Selected >= 0 && ft.Selected < len(ft.Nodes) {
		node := ft.Nodes[ft.Selected]
		if node.IsDir {
			node.Expanded = !node.Expanded
			ft.flatten()
		}
	}
}

// MoveUp moves selection up.
func (ft *FileTree) MoveUp() {
	if ft.Selected > 0 {
		ft.Selected--
	}
}

// MoveDown moves selection down.
func (ft *FileTree) MoveDown() {
	if ft.Selected < len(ft.Nodes)-1 {
		ft.Selected++
	}
}

// SelectedPath returns the path of the selected node.
func (ft *FileTree) SelectedPath() string {
	if ft.Selected >= 0 && ft.Selected < len(ft.Nodes) {
		return ft.Nodes[ft.Selected].Path
	}
	return ""
}

// Render renders the file tree with styling.
func (ft *FileTree) Render(styles Styles, width, maxHeight int) string {
	var sb strings.Builder
	
	// Determine visible range
	start := 0
	end := len(ft.Nodes)
	if end > maxHeight {
		// Center selection in view
		half := maxHeight / 2
		start = ft.Selected - half
		if start < 0 {
			start = 0
		}
		end = start + maxHeight
		if end > len(ft.Nodes) {
			end = len(ft.Nodes)
			start = end - maxHeight
			if start < 0 {
				start = 0
			}
		}
	}
	
	for i := start; i < end; i++ {
		node := ft.Nodes[i]
		
		// Indentation
		indent := strings.Repeat("  ", node.Depth)
		
		// Icon
		var icon string
		if node.IsDir {
			if node.Expanded {
				icon = "📂"
			} else {
				icon = "📁"
			}
		} else {
			icon = getFileIcon(node.Name)
		}
		
		// Name (truncate if needed)
		name := node.Name
		maxNameLen := width - len(indent) - 4
		if len(name) > maxNameLen && maxNameLen > 3 {
			name = name[:maxNameLen-3] + "..."
		}
		
		line := fmt.Sprintf("%s%s %s", indent, icon, name)
		
		if i == ft.Selected {
			sb.WriteString(styles.CommandSelected.Render(line))
		} else if node.IsDir {
			sb.WriteString(styles.Label.Render(line))
		} else {
			sb.WriteString(styles.Muted.Render(line))
		}
		
		if i < end-1 {
			sb.WriteString("\n")
		}
	}
	
	// Scroll indicators
	if start > 0 {
		sb.WriteString("\n" + styles.Muted.Render("  ↑ more"))
	}
	if end < len(ft.Nodes) {
		sb.WriteString("\n" + styles.Muted.Render("  ↓ more"))
	}
	
	return sb.String()
}

// getFileIcon returns an appropriate icon for a file.
func getFileIcon(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	
	icons := map[string]string{
		".go":    "🔷",
		".py":    "🐍",
		".js":    "📜",
		".ts":    "📘",
		".html":  "🌐",
		".css":   "🎨",
		".json":  "📋",
		".yaml":  "📋",
		".yml":   "📋",
		".md":    "📝",
		".txt":   "📄",
		".log":   "📜",
		".sh":    "⚙️",
		".bash":  "⚙️",
		".ps1":   "⚙️",
		".bat":   "⚙️",
		".exe":   "⚡",
		".dll":   "📦",
		".so":    "📦",
		".conf":  "⚙️",
		".cfg":   "⚙️",
		".ini":   "⚙️",
		".mp3":   "🎵",
		".mp4":   "🎬",
		".avi":   "🎬",
		".mkv":   "🎬",
		".jpg":   "🖼️",
		".jpeg":  "🖼️",
		".png":   "🖼️",
		".gif":   "🖼️",
		".pdf":   "📕",
		".zip":   "📦",
		".tar":   "📦",
		".gz":    "📦",
	}
	
	if icon, ok := icons[ext]; ok {
		return icon
	}
	return "📄"
}

// QuickSystemTree creates a tree of important system locations.
func QuickSystemTree() *FileTree {
	// Create a virtual tree of important CyberPatriot locations
	root := &FileTreeNode{
		Name:     "System",
		Path:     "/",
		IsDir:    true,
		Expanded: true,
	}
	
	// Add important directories based on OS
	if isWindows() {
		root.Children = []*FileTreeNode{
			{Name: "Users", Path: "C:\\Users", IsDir: true, Depth: 1},
			{Name: "Program Files", Path: "C:\\Program Files", IsDir: true, Depth: 1},
			{Name: "Windows\\System32", Path: "C:\\Windows\\System32", IsDir: true, Depth: 1},
		}
	} else {
		root.Children = []*FileTreeNode{
			{Name: "/home", Path: "/home", IsDir: true, Depth: 1},
			{Name: "/etc", Path: "/etc", IsDir: true, Depth: 1},
			{Name: "/var/log", Path: "/var/log", IsDir: true, Depth: 1},
			{Name: "/tmp", Path: "/tmp", IsDir: true, Depth: 1},
		}
	}
	
	ft := &FileTree{Root: root}
	ft.flatten()
	return ft
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}

