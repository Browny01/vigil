package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseStat(t *testing.T) {
	fields := []string{"S", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "20", "30", "0", "0", "0", "0", "4", "0", "12345", "100000", "42"}
	p, e := parseStat("77 (a tricky ) process) " + strings.Join(fields, " "))
	if e != nil || p.Name != "a tricky ) process" || p.Ticks != 50 || p.Start != 12345 || p.Threads != 4 || p.RAM != 42*uint64(os.Getpagesize()) {
		t.Fatalf("bad parse: %+v %v", p, e)
	}
	for _, s := range []string{"", "123 no brackets", "2 (x) S 1"} {
		if _, e := parseStat(s); e == nil {
			t.Fatalf("accepted invalid stat %q", s)
		}
	}
}
func TestAuthenticationAndReadOnly(t *testing.T) {
	c := newCollector(t.TempDir(), false)
	s := &server{c: c, password: sha256.Sum256([]byte("correct-test-password")), sessions: map[string]time.Time{}, attempts: map[string][]time.Time{}}
	h := s.handler()
	request := func(method, path, body string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://vigil.test"+path, strings.NewReader(body))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("X-Vigil-Request", "1")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/snapshot", "", nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/login", `{"password":"wrong"}`, nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/login", `{"password":"correct-test-password"}`, nil, "http://evil.test"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := request("POST", "/api/login", `{"password":"correct-test-password"}`, nil, "http://vigil.test")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	if w := request("GET", "/api/snapshot", "", cookie, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/process/9999/signal", `{"start":1,"signal":"TERM"}`, cookie, "http://vigil.test"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	request("POST", "/api/logout", "{}", cookie, "http://vigil.test")
	if w := request("GET", "/api/snapshot", "", cookie, ""); w.Code != 401 {
		t.Fatal("session survived logout")
	}
	for i := 0; i < 6; i++ {
		w = request("POST", "/api/login", `{"password":"wrong"}`, nil, "")
	}
	if w.Code != 429 {
		t.Fatal("missing rate limit")
	}
}
func TestSafeSignalChild(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Process.Kill()
	defer cmd.Wait()
	c := newCollector(t.TempDir(), true)
	p, e := parseStat(read("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/stat"))
	if e != nil {
		t.Fatal(e)
	}
	if e := signalProcess(c, cmd.Process.Pid, p.Start+1, syscall.SIGTERM); e == nil {
		t.Fatal("accepted stale process identity")
	}
	if e := signalProcess(c, os.Getpid(), p.Start, syscall.SIGTERM); e == nil {
		t.Fatal("allowed self termination")
	}
	if e := signalProcess(c, cmd.Process.Pid, p.Start, syscall.SIGTERM); e != nil {
		t.Fatal(e)
	}
}
func TestLiveCollectorAndHistory(t *testing.T) {
	c := newCollector(t.TempDir(), false)
	c.sample()
	time.Sleep(30 * time.Millisecond)
	c.sample()
	if c.current.Total == 0 || len(c.current.Cores) == 0 || len(c.current.Processes) == 0 {
		t.Fatal("missing host metrics")
	}
	if c.current.CPU < 0 || c.current.CPU > 100 {
		t.Fatal("invalid CPU")
	}
	c.save()
	other := newCollector(c.stateDir, false)
	if len(other.history) != 2 {
		t.Fatal("history not restored")
	}
	if c.current.DockerAvailable {
		raw, err := exec.Command("docker", "ps", "-a", "--format", "{{.ID}}").Output()
		if err == nil && strings.TrimSpace(string(raw)) != "" {
			count := 0
			for _, w := range c.current.Workloads {
				if w.Kind == "container" {
					count++
				}
			}
			if count == 0 {
				t.Fatal("Docker discovery returned no containers despite existing containers")
			}
		}
	}
	b, e := json.Marshal(c.current)
	if e != nil || len(b) == 0 {
		t.Fatal("snapshot invalid", e)
	}
}
