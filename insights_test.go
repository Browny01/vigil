package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOwnershipGrouping(t *testing.T) {
	service, container := cgroupLabels("0::/system.slice/docker-" + strings.Repeat("a", 64) + ".scope")
	if service != "" || container != strings.Repeat("a", 64) {
		t.Fatal(service, container)
	}
	service, _ = cgroupLabels("0::/user.slice/user-1000.slice/user@1000.service/app.slice/vigil.service")
	if service != "vigil.service" {
		t.Fatal(service)
	}
	ps := []Process{{PID: 1, Name: "systemd", UID: 0}, {PID: 10, PPID: 1, UID: 1000, Name: "bash", Executable: "/bin/bash"}, {PID: 11, PPID: 10, UID: 1000, Name: "browser", Executable: "/opt/browser"}, {PID: 12, PPID: 11, UID: 1000, Name: "renderer", Executable: "/opt/browser", CPU: 10, RAM: 100}, {PID: 13, PPID: 10, UID: 1000, Name: "node", Executable: "/usr/bin/node", Command: "node /app/a.js"}, {PID: 14, PPID: 10, UID: 1000, Name: "node", Executable: "/usr/bin/node", Command: "node /app/b.js"}}
	gs := groupProcesses(ps)
	if ps[2].Group != ps[3].Group {
		t.Fatal("browser child not grouped")
	}
	if ps[4].Group == ps[5].Group {
		t.Fatal("unrelated node applications combined")
	}
	found := false
	for _, g := range gs {
		if g.Key == ps[2].Group {
			found = g.Count == 2 && g.RAM == 100 && g.CPU == 10
		}
	}
	if !found {
		t.Fatal("aggregate totals wrong")
	}
	ps = []Process{{PID: 100, UID: 0, Service: "daemon.service", ServiceScope: "system", CPU: 2}, {PID: 101, UID: 999, Service: "daemon.service", ServiceScope: "system", CPU: 3}, {PID: 102, UID: 1000, Service: "daemon.service", ServiceScope: "user"}}
	gs = groupProcesses(ps)
	if len(gs) != 2 || ps[0].Group != ps[1].Group || ps[0].Group == ps[2].Group {
		t.Fatal("service scopes mixed", gs)
	}
}
func TestPressureAndRollups(t *testing.T) {
	p := parsePressure("some avg10=12.25 avg60=3 avg300=2 total=200\nfull avg10=2.50 avg60=1 total=100")
	if !p.Available || p.Some != 12.25 || p.Full != 2.5 {
		t.Fatal(p)
	}
	if parsePressure("").Available {
		t.Fatal("missing PSI reported as zero")
	}
	points := []Point{}
	for i := 0; i < 1000; i++ {
		points = appendPoint(points, Point{Time: int64(i) * 60000, CPU: float64(i)}, 60000, 10)
	}
	if len(points) != 10 || points[0].Time != 990*60000 {
		t.Fatal("retention not bounded")
	}
	points = appendPoint(points, Point{Time: 999*60000 + 2000, CPU: 1}, 60000, 10)
	if points[9].CPU != 500 {
		t.Fatal("rollup average wrong", points[9])
	}
	c := newCollector(t.TempDir(), false)
	now := time.Now().UnixMilli()
	s := Snapshot{Point: Point{Time: now}, Processes: []Process{{PID: 5, Start: 10, Name: "test", RAM: 100}}, Groups: []Group{{Key: "app:test", Name: "test", Count: 1, RAM: 100}}}
	c.record(s)
	s.Time += 10000
	s.Processes[0].Start = 11
	c.record(s)
	if len(c.archive.Tracks) != 3 {
		t.Fatal("PID reuse mixed histories", len(c.archive.Tracks))
	}
	s.Time += 10000
	s.Groups[0].LeaderStart = 500
	c.record(s)
	trail := c.archive.Tracks["app:test"].Recent
	if trail[len(trail)-1].Restarts != 1 {
		t.Fatal("application leader change not marked")
	}
	s.Time += 10000
	c.record(s)
	trail = c.archive.Tracks["app:test"].Recent
	if trail[len(trail)-1].Restarts != 0 {
		t.Fatal("restart marked more than once")
	}
	c.save()
	other := newCollector(c.stateDir, false)
	if len(other.archive.Tracks) != 3 {
		t.Fatal("archive not restored")
	}
	if mode, _ := os.Stat(filepath.Join(c.stateDir, "archive.json.gz")); mode.Mode().Perm() != 0600 {
		t.Fatal("history permissions")
	}
}
func TestSustainedAlertLifecycle(t *testing.T) {
	a := newAlerts(t.TempDir())
	r := a.state.Rules["cpu"]
	r.Seconds = 10
	a.state.Rules["cpu"] = r
	s := Snapshot{Point: Point{Time: 1000, CPU: 99}}
	if len(a.evaluate(s)) != 0 {
		t.Fatal("immediate false alert")
	}
	s.Time = 11000
	events := a.evaluate(s)
	if len(events) != 1 || events[0].Resolved != 0 {
		t.Fatal(events)
	}
	s.Time = 15000
	if len(a.evaluate(s)) != 1 {
		t.Fatal("duplicate alert")
	}
	s.Time = 17000
	s.CPU = 10
	events = a.evaluate(s)
	if events[0].Resolved != 17000 {
		t.Fatal("not resolved")
	}
	restored := newAlerts(filepath.Dir(a.path))
	if len(restored.state.Events) != 1 {
		t.Fatal("alerts not persisted")
	}
	rules := defaultRules()
	r = rules["cpu"]
	r.Threshold = 101
	rules["cpu"] = r
	if validateRules(rules) == nil {
		t.Fatal("bad threshold accepted")
	}
}
func TestMonitoringEndpointsRequireAuth(t *testing.T) {
	c := newCollector(t.TempDir(), false)
	s := &server{c: c, sessions: map[string]time.Time{"test": time.Now().Add(time.Hour)}}
	h := s.handler()
	for _, path := range []string{"/api/usage?key=x", "/api/alerts", "/api/history?range=86400000"} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal(path, w.Code)
		}
		r = httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: "vigil_session", Value: "test"})
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
		var result any
		if json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatal("invalid JSON", path)
		}
	}
	r := httptest.NewRequest("POST", "/api/alerts/settings", strings.NewReader(`{}`))
	r.AddCookie(&http.Cookie{Name: "vigil_session", Value: "test"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF check")
	}
}
