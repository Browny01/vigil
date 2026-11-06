package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func itoa(v int) string       { return strconv.Itoa(v) }
func uintstr(v uint64) string { return strconv.FormatUint(v, 10) }

type Group struct {
	Icon        string  `json:"icon,omitempty"`
	LeaderStart uint64  `json:"leaderStart"`
	Scope       string  `json:"scope,omitempty"`
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Kind        string  `json:"kind"`
	User        string  `json:"user"`
	Service     string  `json:"service"`
	Container   string  `json:"container"`
	CPU         float64 `json:"cpu"`
	RAM         uint64  `json:"ram"`
	Count       int     `json:"count"`
	PIDs        []int   `json:"pids"`
}
type Pressure struct {
	Some      float64 `json:"some"`
	Full      float64 `json:"full"`
	Available bool    `json:"available"`
}
type Workload struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	State    string  `json:"state"`
	Detail   string  `json:"detail"`
	Restarts int     `json:"restarts"`
	CPU      float64 `json:"cpu"`
	RAM      uint64  `json:"ram"`
	Count    int     `json:"count"`
}

func parsePressure(s string) Pressure {
	var p Pressure
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		for _, v := range f[1:] {
			if strings.HasPrefix(v, "avg10=") {
				p.Available = true
				if f[0] == "some" {
					p.Some = realnum(strings.TrimPrefix(v, "avg10="))
				}
				if f[0] == "full" {
					p.Full = realnum(strings.TrimPrefix(v, "avg10="))
				}
			}
		}
	}
	return p
}
func cgroupLabels(s string) (string, string) {
	service, container := "", ""
	for _, line := range strings.Split(s, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, part := range strings.Split(parts[2], "/") {
			raw := strings.TrimSuffix(strings.TrimPrefix(part, "docker-"), ".scope")
			if len(raw) == 64 {
				if _, e := strconv.ParseUint(raw[:16], 16, 64); e == nil {
					container = raw
				}
			}
			if strings.HasSuffix(part, ".service") && !strings.HasPrefix(part, "user@") && part != "init.scope" {
				service = part
			}
		}
	}
	return service, container
}
func (c *Collector) metadata(p *Process) {
	if old, ok := c.procs[p.PID]; ok && old.Start == p.Start && time.Since(c.metaAt) < 30*time.Second {
		p.Executable = old.Executable
		p.Command = old.Command
		p.Service = old.Service
		p.ServiceScope = old.ServiceScope
		p.Container = old.Container
		return
	}
	base := filepath.Join(c.procRoot, itoa(p.PID))
	p.Executable, _ = os.Readlink(base + "/exe")
	cmd := strings.Split(read(base+"/cmdline"), "\x00")
	if len(cmd) > 0 {
		n := len(cmd)
		if n > 3 {
			n = 3
		}
		p.Command = strings.Join(cmd[:n], " ")
	}

	cg := read(base + "/cgroup")
	p.Service, p.Container = cgroupLabels(cg)
	p.ServiceScope = "system"
	if strings.Contains(cg, "/user.slice/") {
		p.ServiceScope = "user"
	}
}
func groupProcesses(ps []Process) []Group {
	byPID := map[int]Process{}
	for _, p := range ps {
		byPID[p.PID] = p
	}
	groups := map[string]*Group{}
	for i := range ps {
		p := &ps[i]
		root := *p
		for n := 0; n < 32; n++ {
			parent, ok := byPID[root.PPID]
			if !ok || parent.UID != p.UID || parent.PID <= 1 || parent.PID == root.PID || parent.Name == "systemd" || isShell(parent.Name) || parent.Service != p.Service || parent.Container != p.Container {
				break
			}
			root = parent
		}
		name := filepath.Base(root.Executable)
		if name == "." || name == "" {
			name = root.Name
		}
		if isInterpreter(name) {
			f := strings.Fields(root.Command)
			if len(f) > 2 && f[1] == "-m" {
				name = f[2]
			} else if len(f) > 1 && !strings.HasPrefix(f[1], "-") {
				name = filepath.Base(f[1])
			}
		}
		identity := root.Executable
		if isInterpreter(filepath.Base(root.Executable)) {
			f := strings.Fields(root.Command)
			if len(f) > 2 && f[1] == "-m" {
				identity += ":module:" + f[2]
			} else if len(f) > 1 && !strings.HasPrefix(f[1], "-") {
				identity += ":script:" + f[1]
			} else {
				identity += ":instance:" + itoa(root.PID) + ":" + uintstr(root.Start)
			}
		}
		kind, key := "application", "app:"+itoa(p.UID)+":"+identity+":"+name
		if p.Container != "" {
			kind = "container"
			name = p.Container[:12]
			key = "container:" + p.Container
		} else if p.Service != "" {
			kind = "service"
			name = strings.TrimSuffix(p.Service, ".service")
			key = "service:" + p.ServiceScope + ":" + p.Service
		} else if p.UID == 0 && p.Executable == "" {
			name = "Kernel threads"
			key = "kernel"
			kind = "kernel"
		}
		p.Group = key
		g := groups[key]
		if g == nil {
			g = &Group{Key: key, Name: name, Kind: kind, User: p.User, Service: p.Service, Scope: p.ServiceScope, Container: p.Container, LeaderStart: root.Start}
			groups[key] = g
		}
		if root.Start < g.LeaderStart {
			g.LeaderStart = root.Start
		}
		if g.User != p.User {
			g.User = "mixed"
		}
		g.CPU += p.CPU
		g.RAM += p.RAM
		g.Count++
		g.PIDs = append(g.PIDs, p.PID)
	}
	out := []Group{}
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CPU != out[j].CPU {
			return out[i].CPU > out[j].CPU
		}
		return out[i].Key < out[j].Key
	})
	return out
}
func isShell(s string) bool {
	return s == "bash" || s == "zsh" || s == "sh" || s == "fish" || s == "sshd" || s == "login" || s == "sudo" || s == "su"
}
func isInterpreter(s string) bool {
	return strings.HasPrefix(s, "python") || s == "node" || s == "ruby" || s == "java" || s == "bun"
}
func runRead(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, args[0], args[1:]...).Output()
}
func (c *Collector) workloads(now time.Time) {
	if now.Sub(c.workAt) < 30*time.Second {
		return
	}
	c.workAt = now
	c.workloadList = []Workload{}
	c.dockerAvailable = false
	c.servicesAvailable = false
	for _, scope := range []string{"system", "user"} {
		args := []string{"systemctl"}
		if scope == "user" {
			args = append(args, "--user")
		}
		args = append(args, "show", "--type=service", "--all", "--property=Id,ActiveState,SubState,NRestarts,Description", "--no-pager")
		b, e := runRead(args...)
		if e != nil {
			continue
		}
		c.servicesAvailable = true
		for _, block := range strings.Split(strings.TrimSpace(string(b)), "\n\n") {
			m := map[string]string{}
			for _, l := range strings.Split(block, "\n") {
				f := strings.SplitN(l, "=", 2)
				if len(f) == 2 {
					m[f[0]] = f[1]
				}
			}
			if m["Id"] == "" {
				continue
			}
			c.workloadList = append(c.workloadList, Workload{ID: scope + ":" + m["Id"], Name: m["Id"], Kind: scope, State: m["ActiveState"], Detail: m["Description"] + " / " + m["SubState"], Restarts: int(num(m["NRestarts"]))})
		}
	}
	b, e := runRead("docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}")
	if e == nil {
		c.dockerAvailable = true
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			var m struct{ ID, Names, Image, State, Status string }
			if json.Unmarshal([]byte(l), &m) == nil && m.ID != "" {
				c.workloadList = append(c.workloadList, Workload{ID: m.ID, Name: m.Names, Kind: "container", State: m.State, Detail: m.Image + " / " + m.Status})
			}
		}
	}
}
func (c *Collector) enrich(s *Snapshot) {
	pressure := parsePressure(read(c.procRoot + "/pressure/memory"))
	s.MemoryPressure = pressure
	s.Pressure = pressure.Some
	vm := map[string]uint64{}
	for _, line := range strings.Split(read(c.procRoot+"/vmstat"), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			vm[f[0]] = num(f[1])
		}
	}
	if !c.last.IsZero() {
		dt := float64(s.Time-c.last.UnixMilli()) / 1000
		if dt > 0 {
			if vm["pswpin"] >= c.swap[0] {
				s.SwapIn = float64(vm["pswpin"]-c.swap[0]) * float64(os.Getpagesize()) / dt
			}
			if vm["pswpout"] >= c.swap[1] {
				s.SwapOut = float64(vm["pswpout"]-c.swap[1]) * float64(os.Getpagesize()) / dt
			}
		}
	}
	c.swap = [2]uint64{vm["pswpin"], vm["pswpout"]}
	s.Groups = groupProcesses(s.Processes)
	s.Boot = c.boot
	c.workloads(time.Now())
	s.Workloads = append([]Workload{}, c.workloadList...)
	s.DockerAvailable = c.dockerAvailable
	s.ServicesAvailable = c.servicesAvailable
	for i := range s.Workloads {
		w := &s.Workloads[i]
		for j := range s.Groups {
			g := &s.Groups[j]
			match := w.Kind == "container" && g.Container == w.ID || w.Kind != "container" && g.Service == w.Name && w.Kind == g.Scope
			if match {
				w.CPU += g.CPU
				w.RAM += g.RAM
				w.Count += g.Count
				if w.Kind == "container" {
					g.Name = w.Name
				}
			}
		}
	}
}
