package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type AlertRule struct {
	Enabled   bool    `json:"enabled"`
	Threshold float64 `json:"threshold"`
	Seconds   int     `json:"seconds"`
}
type Alert struct {
	ID           string `json:"id"`
	Key          string `json:"key"`
	Title        string `json:"title"`
	Detail       string `json:"detail"`
	Time         int64  `json:"time"`
	Resolved     int64  `json:"resolved,omitempty"`
	Acknowledged bool   `json:"acknowledged"`
}
type alertState struct {
	Rules  map[string]AlertRule `json:"rules"`
	Events []Alert              `json:"events"`
}
type AlertManager struct {
	mu      sync.Mutex
	state   alertState
	since   map[string]int64
	path    string
	webhook string
	queue   chan Alert
}

func defaultRules() map[string]AlertRule {
	return map[string]AlertRule{
		"cpu": {true, 90, 60}, "memory": {true, 95, 60}, "pressure": {true, 10, 30}, "swap": {true, 1048576, 30}, "disk": {true, 90, 60}, "temperature": {true, 85, 30}, "service": {true, 1, 30}, "container": {true, 1, 30},
	}
}
func newAlerts(state string) *AlertManager {
	a := &AlertManager{state: alertState{Rules: defaultRules(), Events: []Alert{}}, since: map[string]int64{}, path: filepath.Join(state, "alerts.json"), queue: make(chan Alert, 32)}
	b, e := os.ReadFile(a.path)
	if e == nil {
		var saved alertState
		if json.Unmarshal(b, &saved) == nil {
			if validateRules(saved.Rules) == nil {
				a.state.Rules = saved.Rules
			}
			a.state.Events = saved.Events
			if len(a.state.Events) > 200 {
				a.state.Events = a.state.Events[len(a.state.Events)-200:]
			}
		}
	}
	return a
}
func validateRules(rules map[string]AlertRule) error {
	defaults := defaultRules()
	if len(rules) != len(defaults) {
		return fmt.Errorf("all alert rules must be supplied")
	}
	for k, r := range rules {
		if _, ok := defaults[k]; !ok {
			return fmt.Errorf("unknown rule")
		}
		if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.Threshold <= 0 || r.Seconds < 2 || r.Seconds > 3600 {
			return fmt.Errorf("thresholds must be positive and durations between 2 and 3600 seconds")
		}
		max := float64(100)
		if k == "temperature" {
			max = 150
		}
		if k == "swap" {
			max = 1 << 40
		}
		if k == "service" || k == "container" {
			max = 1
		}
		if r.Threshold > max {
			return fmt.Errorf("%s threshold is out of range", k)
		}
	}
	return nil
}
func (a *AlertManager) startWebhook(raw string) {
	u, e := url.Parse(raw)
	if raw == "" {
		return
	}
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		log.Print("alert webhook disabled: use a valid HTTPS URL without user credentials")
		return
	}
	a.webhook = raw
	go func() {
		client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		for event := range a.queue {
			b, _ := json.Marshal(map[string]any{"source": "Vigil", "alert": event})
			req, e := http.NewRequest("POST", a.webhook, bytes.NewReader(b))
			if e != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			resp, e := client.Do(req)
			if e != nil {
				log.Print("alert webhook delivery failed")
				continue
			}
			resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				log.Printf("alert webhook returned HTTP %d", resp.StatusCode)
			}
		}
	}()
}
func (a *AlertManager) evaluate(s Snapshot) []Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	type condition struct {
		rule, title, detail string
		value               float64
	}
	conditions := map[string]condition{}
	conditions["cpu"] = condition{"cpu", "Sustained CPU load", fmt.Sprintf("CPU usage is %.1f%%", s.CPU), s.CPU}
	conditions["memory"] = condition{"memory", "Low available memory", fmt.Sprintf("Memory usage is %.1f%%", s.Memory), s.Memory}
	if s.MemoryPressure.Available {
		conditions["pressure"] = condition{"pressure", "Memory pressure", fmt.Sprintf("Tasks stalled for memory %.1f%% of the last 10 seconds", s.Pressure), s.Pressure}
	}
	conditions["swap"] = condition{"swap", "Active swapping", fmt.Sprintf("Swap I/O is %.1f MiB/s", (s.SwapIn+s.SwapOut)/1048576), s.SwapIn + s.SwapOut}
	for _, d := range s.Disks {
		if d.Total > 0 {
			conditions["disk:"+d.Mount] = condition{"disk", "Storage nearly full", d.Mount + " is above its usage threshold", float64(d.Used) / float64(d.Total) * 100}
		}
	}
	for _, sensor := range s.Sensors {
		conditions["temperature:"+sensor.Name] = condition{"temperature", "High temperature", fmt.Sprintf("%s is %.1f °C", sensor.Name, sensor.Celsius), sensor.Celsius}
	}
	for _, g := range s.GPUs {
		conditions["temperature:gpu:"+g.Name] = condition{"temperature", "High GPU temperature", fmt.Sprintf("%s is %.1f °C", g.Name, g.Temperature), g.Temperature}
	}
	for _, w := range s.Workloads {
		rule := "service"
		if w.Kind == "container" {
			rule = "container"
		}
		value := 0.0
		if w.State == "failed" || w.Kind == "container" && (w.State == "restarting" || strings.Contains(w.Detail, "unhealthy")) {
			value = 1
		}
		conditions[rule+":"+w.ID] = condition{rule, "Unhealthy " + rule, w.Name + ": " + w.State + " / " + w.Detail, value}
	}
	for key := range a.since {
		if _, exists := conditions[key]; !exists {
			delete(a.since, key)
		}
	}
	changed := false
	for key, cond := range conditions {
		r := a.state.Rules[cond.rule]
		firing := r.Enabled && cond.value >= r.Threshold
		if firing {
			if a.since[key] == 0 {
				a.since[key] = s.Time
			}
		} else {
			delete(a.since, key)
		}
		active := -1
		for i := len(a.state.Events) - 1; i >= 0; i-- {
			if a.state.Events[i].Key == key && a.state.Events[i].Resolved == 0 {
				active = i
				break
			}
		}
		if firing && s.Time-a.since[key] >= int64(r.Seconds)*1000 && active < 0 {
			event := Alert{ID: token(), Key: key, Title: cond.title, Detail: cond.detail, Time: s.Time}
			a.state.Events = append(a.state.Events, event)
			changed = true
			a.deliver(event)
		}
		if !firing && active >= 0 {
			a.state.Events[active].Resolved = s.Time
			changed = true
			event := a.state.Events[active]
			event.Title = "Resolved: " + event.Title
			a.deliver(event)
		}
	}
	// Workloads that disappear cannot leave an alert permanently active.
	for i := range a.state.Events {
		e := &a.state.Events[i]
		if e.Resolved == 0 {
			if _, exists := conditions[e.Key]; !exists {
				e.Resolved = s.Time
				changed = true
			}
			rule := strings.SplitN(e.Key, ":", 2)[0]
			if !a.state.Rules[rule].Enabled {
				e.Resolved = s.Time
				changed = true
			}
		}
	}
	if len(a.state.Events) > 200 {
		a.state.Events = append([]Alert(nil), a.state.Events[len(a.state.Events)-200:]...)
	}
	if changed {
		a.persist()
	}
	return append([]Alert{}, a.state.Events...)
}
func (a *AlertManager) deliver(e Alert) {
	if a.webhook != "" {
		select {
		case a.queue <- e:
		default:
			log.Print("alert webhook queue full; event remains in alert feed")
		}
	}
}
func (a *AlertManager) persist() {
	if e := writePrivateJSON(a.path, a.state, false); e != nil {
		log.Printf("alert state persistence failed: %v", e)
	}
}
func (a *AlertManager) get() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	rules := map[string]AlertRule{}
	for k, v := range a.state.Rules {
		rules[k] = v
	}
	events := append([]Alert{}, a.state.Events...)
	sort.Slice(events, func(i, j int) bool { return events[i].Time > events[j].Time })
	return map[string]any{"rules": rules, "events": events, "webhookConfigured": a.webhook != ""}
}
func (s *server) monitorRoutes(api func(string, http.HandlerFunc)) {
	api("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if len(key) > 1024 {
			http.Error(w, "Invalid history key", 400)
			return
		}
		writeJSON(w, s.c.usageRange(key, rangeMS(r, 1800000, 7*86400000)))
	})
	api("GET /api/alerts", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.c.alerts.get()) })
	api("POST /api/alerts/settings", func(w http.ResponseWriter, r *http.Request) {
		if !safeOrigin(r) {
			http.Error(w, "Invalid origin", 403)
			return
		}
		var rules map[string]AlertRule
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&rules) != nil {
			http.Error(w, "Invalid rules", 400)
			return
		}
		if e := validateRules(rules); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		a := s.c.alerts
		a.mu.Lock()
		a.state.Rules = rules
		a.since = map[string]int64{}
		a.persist()
		a.mu.Unlock()
		writeJSON(w, map[string]bool{"ok": true})
	})
	api("POST /api/alerts/{id}/ack", func(w http.ResponseWriter, r *http.Request) {
		if !safeOrigin(r) {
			http.Error(w, "Invalid origin", 403)
			return
		}
		a := s.c.alerts
		a.mu.Lock()
		defer a.mu.Unlock()
		for i := range a.state.Events {
			if a.state.Events[i].ID == r.PathValue("id") {
				a.state.Events[i].Acknowledged = true
				a.persist()
				writeJSON(w, map[string]bool{"ok": true})
				return
			}
		}
		http.Error(w, "Alert no longer exists", 404)
	})
}
func rangeMS(r *http.Request, def, max int64) int64 {
	n, e := time.ParseDuration(r.URL.Query().Get("range") + "ms")
	if e != nil || n < time.Minute || n.Milliseconds() > max {
		return def
	}
	return n.Milliseconds()
}
