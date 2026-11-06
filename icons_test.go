package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDesktopIdentityParsing(t *testing.T) {
	f := desktopFields("[Desktop Entry]\nType=Application\nName=Example Browser\nIcon=example.browser\nExec=\"/opt/Example Browser/browser\" --profile %U\n[Desktop Action NewWindow]\nName=Wrong\nIcon=wrong")
	if f["Name"] != "Example Browser" || f["Icon"] != "example.browser" {
		t.Fatal(f)
	}
	words := execWords(f["Exec"])
	if len(words) != 3 || words[0] != "/opt/Example Browser/browser" {
		t.Fatal(words)
	}
	if appAlias("/opt/zen-browser/zen-bin") != appAlias("Zen Browser") {
		t.Fatal("binary alias not normalized")
	}
}
func TestIconAllowlistAndAuthentication(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	image := filepath.Join(root, "example.svg")
	if e := os.WriteFile(image, []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path d="M1 1h14v14H1z"/></svg>`), 0600); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(outside, "private.png"), []byte("private"), 0600)
	os.Symlink(filepath.Join(outside, "private.png"), filepath.Join(root, "escape.png"))
	if !iconAllowed(image, []string{root}) || iconAllowed(filepath.Join(root, "escape.png"), []string{root}) {
		t.Fatal("icon paths escaped allowed roots")
	}
	c := newCollector(t.TempDir(), false)
	c.icons = &IconCatalog{files: map[string]string{"known": image}, aliases: map[string]appIdentity{}}
	s := &server{c: c, sessions: map[string]time.Time{"session": time.Now().Add(time.Minute)}}
	h := s.handler()
	for _, tc := range []struct {
		path string
		auth bool
		code int
	}{{"/api/icons/known", false, 401}, {"/api/icons/known", true, 200}, {"/api/icons/unknown", true, 404}, {"/api/icons/private.png", true, 404}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		if tc.auth {
			r.AddCookie(&http.Cookie{Name: "vigil_session", Value: "session"})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s got %d", tc.path, w.Code)
		}
		if w.Code == 200 {
			if w.Header().Get("Content-Type") != "image/svg+xml" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
				t.Fatal("unsafe SVG headers")
			}
		}
	}
}
func TestIconDecorationPreservesIdentity(t *testing.T) {
	c := newCollector(t.TempDir(), false)
	c.icons = &IconCatalog{aliases: map[string]appIdentity{"browser": {Name: "Example Browser", Icon: "abc"}}}
	s := Snapshot{Groups: []Group{{Key: "stable", Name: "browser", Kind: "application"}}, Processes: []Process{{Group: "stable", Executable: "/opt/browser"}}}
	c.decorateApplications(&s)
	if s.Groups[0].Key != "stable" || s.Groups[0].Icon != "abc" || s.Groups[0].Name != "Example Browser" {
		t.Fatal(s.Groups)
	}
}
