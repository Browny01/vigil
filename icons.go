package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type appIdentity struct{ Name, Icon string }
type IconCatalog struct {
	mu      sync.RWMutex
	aliases map[string]appIdentity
	files   map[string]string
}

func appAlias(s string) string {
	s = strings.ToLower(filepath.Base(s))
	s = strings.TrimSuffix(s, ".desktop")
	s = strings.ReplaceAll(s, " ", "-")
	for _, suffix := range []string{"-bin", "-stable", "-browser"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(s)
}
func desktopFields(text string) map[string]string {
	fields := map[string]string{}
	active := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			active = line == "[Desktop Entry]"
			continue
		}
		if !active || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.SplitN(line, "=", 2)
		if len(p) == 2 {
			fields[p[0]] = p[1]
		}
	}
	return fields
}

// Tokenize desktop Exec without invoking a shell or expanding variables.
func execWords(s string) []string {
	words := []string{}
	var b strings.Builder
	quote := rune(0)
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == ' ' || r == '\t' {
			if b.Len() > 0 {
				words = append(words, b.String())
				b.Reset()
			}
		} else {
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		words = append(words, b.String())
	}
	return words
}
func iconAllowed(path string, roots []string) bool {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return false
	}
	for _, root := range roots {
		rel, e := filepath.Rel(root, resolved)
		if e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			ext := strings.ToLower(filepath.Ext(resolved))
			return ext == ".png" || ext == ".svg" || ext == ".jpg" || ext == ".jpeg" || ext == ".webp"
		}
	}
	return false
}
func newIconCatalog() *IconCatalog {
	home, _ := os.UserHomeDir()
	c := &IconCatalog{aliases: map[string]appIdentity{}, files: map[string]string{}}
	allowed := []string{filepath.Join(home, ".local/share/icons"), filepath.Join(home, ".local/share/applications"), filepath.Join(home, "Applications"), "/usr/share", "/usr/lib", "/opt"}
	iconRoots := []string{filepath.Join(home, ".local/share/icons"), "/usr/share/icons", "/usr/share/pixmaps"}
	named := map[string]string{}
	score := map[string]int{}
	for _, root := range iconRoots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
			if e != nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".png" && ext != ".svg" {
				return nil
			}
			if !strings.Contains(path, "/apps/") && !strings.HasPrefix(path, "/usr/share/pixmaps/") {
				return nil
			}
			name := strings.TrimSuffix(filepath.Base(path), ext)
			rank := 1
			if strings.Contains(path, "/hicolor/") {
				rank += 10
			}
			if strings.Contains(path, "/48x48/") || strings.Contains(path, "/64x64/") {
				rank += 20
			}
			if strings.Contains(path, "/128x128/") {
				rank += 15
			}
			if ext == ".svg" {
				rank += 5
			}
			if rank > score[name] {
				named[name] = path
				score[name] = rank
			}
			return nil
		})
	}
	dirs := []string{"/usr/share/applications", "/usr/local/share/applications", "/var/lib/flatpak/exports/share/applications", filepath.Join(home, ".local/share/flatpak/exports/share/applications"), filepath.Join(home, ".local/share/applications")}
	for _, dir := range dirs {
		paths, _ := filepath.Glob(filepath.Join(dir, "*.desktop"))
		sort.Strings(paths)
		for _, path := range paths {
			f := desktopFields(read(path))
			if f["Type"] != "Application" || f["Hidden"] == "true" || f["Icon"] == "" {
				continue
			}
			icon := f["Icon"]
			if !filepath.IsAbs(icon) {
				icon = named[strings.TrimSuffix(icon, filepath.Ext(icon))]
				if icon == "" {
					icon = named[f["Icon"]]
				}
			}
			if icon == "" || !iconAllowed(icon, allowed) {
				continue
			}
			st, e := os.Stat(icon)
			if e != nil || !st.Mode().IsRegular() || st.Size() > 2<<20 {
				continue
			}
			sum := sha256.Sum256([]byte(icon))
			id := hex.EncodeToString(sum[:12])
			c.files[id] = icon
			aliases := []string{filepath.Base(path), f["Name"], f["TryExec"], f["StartupWMClass"]}

			words := execWords(f["Exec"])
			if len(words) > 0 {
				command := filepath.Base(words[0])
				generic := isInterpreter(command) || isShell(command) || command == "electron" || command == "xdg-open" || command == "flatpak" || command == "uwsm" || command == "omarchy" || command == "env"
				if !generic {
					terminal := false
					for _, w := range words[1:] {
						if w == "-e" {
							terminal = true
						}
					}
					if !terminal {
						aliases = append(aliases, words[0])
					}
				} else if isInterpreter(command) || command == "electron" {
					if len(words) > 2 && words[1] == "-m" {
						aliases = append(aliases, words[2])
					} else if len(words) > 1 && !strings.HasPrefix(words[1], "-") {
						aliases = append(aliases, words[1])
					}
				}
			}

			for _, alias := range aliases {
				if alias != "" {
					c.aliases[appAlias(alias)] = appIdentity{f["Name"], id}
				}
			}
		}
	}
	// The project's own installed identity is also available in portable installs.
	sum := sha256.Sum256([]byte("vigil-embedded"))
	id := hex.EncodeToString(sum[:12])
	c.files[id] = "@vigil"
	c.aliases["vigil"] = appIdentity{"Vigil", id}
	return c
}
func (c *IconCatalog) match(values ...string) (appIdentity, bool) {
	if c == nil {
		return appIdentity{}, false
	}
	for _, v := range values {
		if identity, ok := c.aliases[appAlias(v)]; ok {
			return identity, true
		}
	}
	return appIdentity{}, false
}
func (c *Collector) decorateApplications(s *Snapshot) {
	if c.icons == nil {
		return
	}
	for i := range s.Groups {
		g := &s.Groups[i]
		identity, found := c.icons.match(g.Name)
		if !found && g.Kind != "container" && g.Kind != "kernel" {
			for _, p := range s.Processes {
				if p.Group == g.Key {
					identity, found = c.icons.match(p.Executable, p.Name)
					if found {
						break
					}
				}
			}
		}
		if found {
			g.Icon = identity.Icon
			if g.Kind == "application" {
				g.Name = identity.Name
			}
		}
	}
}
func (s *server) iconHandler(w http.ResponseWriter, r *http.Request) {
	if s.c.icons == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	s.c.icons.mu.RLock()
	path, ok := s.c.icons.files[id]
	s.c.icons.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	var data []byte
	var e error
	if path == "@vigil" {
		data, e = assets.ReadFile("web/app-icon.png")
	} else {
		f, err := os.Open(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		data, e = io.ReadAll(io.LimitReader(bufio.NewReader(f), (2<<20)+1))
	}
	if e != nil || len(data) > 2<<20 {
		http.NotFound(w, r)
		return
	}
	mime := http.DetectContentType(data)
	if strings.HasSuffix(path, ".svg") {
		if !strings.Contains(string(data), "<svg") {
			http.NotFound(w, r)
			return
		}
		mime = "image/svg+xml"
	}
	if !strings.HasPrefix(mime, "image/") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(data)
}
