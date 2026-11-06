package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type Usage struct {
	Generation string  `json:"generation,omitempty"`
	Restarts   int     `json:"restarts,omitempty"`
	Time       int64   `json:"time"`
	CPU        float64 `json:"cpu"`
	RAM        uint64  `json:"ram"`
	Count      int     `json:"count"`
	Samples    int     `json:"samples"`
}
type Track struct {
	Name    string  `json:"name"`
	Kind    string  `json:"kind"`
	Last    int64   `json:"last"`
	Recent  []Usage `json:"recent"`
	Minutes []Usage `json:"minutes,omitempty"`
	Hours   []Usage `json:"hours,omitempty"`
}
type Archive struct {
	Minutes []Point           `json:"minutes"`
	Hours   []Point           `json:"hours"`
	Tracks  map[string]*Track `json:"tracks"`
}

func usageKey(boot string, p Process) string {
	return "pid:" + boot + ":" + itoa(p.PID) + ":" + uintstr(p.Start)
}
func appendUsage(a []Usage, u Usage, width int64, limit int) []Usage {
	u.Time = u.Time / width * width
	u.Samples = 1
	if len(a) > 0 && a[len(a)-1].Time == u.Time {
		v := &a[len(a)-1]
		n := float64(v.Samples)
		v.CPU = (v.CPU*n + u.CPU) / (n + 1)
		v.RAM = uint64((float64(v.RAM)*n + float64(u.RAM)) / (n + 1))
		v.Count = u.Count
		v.Restarts += u.Restarts
		v.Generation = u.Generation
		v.Samples++
		return a
	}
	a = append(a, u)
	if len(a) > limit {
		copy(a, a[len(a)-limit:])
		a = a[:limit]
	}
	return a
}
func appendPoint(a []Point, p Point, width int64, limit int) []Point {
	p.Time = p.Time / width * width
	p.Samples = 1
	if len(a) > 0 && a[len(a)-1].Time == p.Time && (a[len(a)-1].BootID == p.BootID || a[len(a)-1].BootID == "" || p.BootID == "") {
		v := &a[len(a)-1]
		n := float64(v.Samples)
		avg := func(x, y float64) float64 { return (x*n + y) / (n + 1) }
		v.CPU = avg(v.CPU, p.CPU)
		v.Memory = avg(v.Memory, p.Memory)
		v.RX = avg(v.RX, p.RX)
		v.TX = avg(v.TX, p.TX)
		v.Read = avg(v.Read, p.Read)
		v.Write = avg(v.Write, p.Write)
		v.Pressure = avg(v.Pressure, p.Pressure)
		v.SwapIn = avg(v.SwapIn, p.SwapIn)
		v.SwapOut = avg(v.SwapOut, p.SwapOut)
		v.Samples++
		return a
	}
	a = append(a, p)
	if len(a) > limit {
		copy(a, a[len(a)-limit:])
		a = a[:limit]
	}
	return a
}
func (c *Collector) record(s Snapshot) {
	a := &c.archive
	if a.Tracks == nil {
		a.Tracks = map[string]*Track{}
	}
	a.Minutes = appendPoint(a.Minutes, s.Point, 60000, 7*24*60)
	a.Hours = appendPoint(a.Hours, s.Point, 3600000, 90*24)
	if s.Time-c.lastUsage < 10000 {
		return
	}
	c.lastUsage = s.Time
	active := map[string]Usage{}
	names := map[string]string{}
	ps := append([]Process(nil), s.Processes...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].RAM > ps[j].RAM })
	if len(ps) > 512 {
		ps = ps[:512]
	}
	for _, p := range ps {
		key := usageKey(c.boot, p)
		active[key] = Usage{Time: s.Time, CPU: p.CPU, RAM: p.RAM, Count: 1}
		names[key] = p.Name
	}
	gs := append([]Group(nil), s.Groups...)
	sort.Slice(gs, func(i, j int) bool { return gs[i].RAM > gs[j].RAM })
	if len(gs) > 128 {
		gs = gs[:128]
	}
	for _, g := range gs {
		active[g.Key] = Usage{Time: s.Time, CPU: g.CPU, RAM: g.RAM, Count: g.Count, Generation: c.boot + ":" + uintstr(g.LeaderStart)}
		names[g.Key] = g.Name
	}
	for key, u := range active {
		t := a.Tracks[key]
		if t == nil {
			kind := "application"
			if len(key) > 4 && key[:4] == "pid:" {
				kind = "process"
			}
			t = &Track{Name: names[key], Kind: kind}
			a.Tracks[key] = t
		}
		if t.Kind == "application" && len(t.Recent) > 0 && t.Recent[len(t.Recent)-1].Generation != "" && t.Recent[len(t.Recent)-1].Generation != u.Generation {
			u.Restarts = 1
		}
		t.Last = s.Time
		t.Recent = appendUsage(t.Recent, u, 10000, 180)
		if t.Kind == "application" {
			t.Minutes = appendUsage(t.Minutes, u, 60000, 1440)
			t.Hours = appendUsage(t.Hours, u, 3600000, 168)
		}
	}
	// Exited identities keep a short trail; application identities survive restarts.
	keys := make([]string, 0, len(a.Tracks))
	for k, t := range a.Tracks {
		ttl := int64(time.Hour / time.Millisecond)
		if t.Kind == "application" {
			ttl = int64(7 * 24 * time.Hour / time.Millisecond)
		}
		if s.Time-t.Last > ttl {
			delete(a.Tracks, k)
		} else {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return a.Tracks[keys[i]].Last > a.Tracks[keys[j]].Last })
	procs, groups := 0, 0
	for _, k := range keys {
		if a.Tracks[k].Kind == "process" {
			procs++
			if procs > 512 {
				delete(a.Tracks, k)
			}
		} else {
			groups++
			if groups > 128 {
				delete(a.Tracks, k)
			}
		}
	}
}
func (c *Collector) historyRange(ms int64) []Point {
	c.mu.RLock()
	defer c.mu.RUnlock()
	source := c.history
	if ms > 3600000 {
		source = c.archive.Minutes
	}
	if ms > 7*86400000 {
		source = c.archive.Hours
	}
	out := []Point{}
	cut := time.Now().UnixMilli() - ms
	for _, p := range source {
		if p.Time >= cut {
			out = append(out, p)
		}
	}
	return out
}
func (c *Collector) usageRange(key string, ms int64) map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t := c.archive.Tracks[key]
	if t == nil {
		return map[string]any{"points": []Usage{}, "name": "", "kind": "", "last": 0}
	}
	source := t.Recent
	if ms > 1800000 && t.Kind == "application" {
		source = t.Minutes
	}
	if ms > 86400000 && t.Kind == "application" {
		source = t.Hours
	}
	out := []Usage{}
	cut := time.Now().UnixMilli() - ms
	for _, p := range source {
		if p.Time >= cut {
			out = append(out, p)
		}
	}
	return map[string]any{"points": out, "name": t.Name, "kind": t.Kind, "last": t.Last}
}
func (c *Collector) loadArchive() {
	path := filepath.Join(c.stateDir, "archive.json.gz")
	f, e := os.Open(path)
	if e != nil {
		return
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		return
	}
	defer z.Close()
	var a Archive
	if json.NewDecoder(io.LimitReader(z, 128<<20)).Decode(&a) == nil {
		c.archive = a
	}
}
func writePrivateJSON(path string, v any, compressed bool) error {
	f, e := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	var writer io.Writer = f
	var z *gzip.Writer
	if compressed {
		z, _ = gzip.NewWriterLevel(f, gzip.BestSpeed)
		writer = z
	}
	e = json.NewEncoder(writer).Encode(v)
	if z != nil {
		if closeErr := z.Close(); e == nil {
			e = closeErr
		}
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}
func (c *Collector) saveArchive() {
	c.mu.RLock()
	b, e := json.Marshal(c.archive)
	c.mu.RUnlock()
	if e != nil {
		return
	}
	path := filepath.Join(c.stateDir, "archive.json.gz")
	f, e := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		log.Printf("history persistence failed: %v", e)
		return
	}
	z, _ := gzip.NewWriterLevel(f, gzip.BestSpeed)
	_, e = z.Write(b)
	if closeErr := z.Close(); e == nil {
		e = closeErr
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e == nil {
		e = os.Rename(path+".tmp", path)
	}
	if e != nil {
		log.Printf("history persistence failed: %v", e)
	}

}
