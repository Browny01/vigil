package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type CPUTime struct{ Total, Idle uint64 }
type Process struct {
	ServiceScope string   `json:"serviceScope,omitempty"`
	Group        string   `json:"group"`
	Executable   string   `json:"executable,omitempty"`
	Command      string   `json:"-"`
	Service      string   `json:"service,omitempty"`
	Container    string   `json:"container,omitempty"`
	PID          int      `json:"pid"`
	PPID         int      `json:"ppid"`
	Name         string   `json:"name"`
	State        string   `json:"state"`
	User         string   `json:"user"`
	UID          int      `json:"uid"`
	CPU          float64  `json:"cpu"`
	RAM          uint64   `json:"ram"`
	Threads      int      `json:"threads"`
	Start        uint64   `json:"start"`
	Ticks        uint64   `json:"-"`
	GPUMemory    *uint64  `json:"gpuMemory,omitempty"`
	GPUUsage     *float64 `json:"gpuUsage,omitempty"`
}
type Disk struct {
	Name  string `json:"name"`
	Mount string `json:"mount"`
	FS    string `json:"fs"`
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}
type Network struct {
	Name     string  `json:"name"`
	RX       float64 `json:"rx"`
	TX       float64 `json:"tx"`
	Received uint64  `json:"received"`
	Sent     uint64  `json:"sent"`
}
type Sensor struct {
	Name    string  `json:"name"`
	Celsius float64 `json:"celsius"`
}
type GPU struct {
	Name        string  `json:"name"`
	Usage       float64 `json:"usage"`
	Memory      uint64  `json:"memory"`
	Total       uint64  `json:"total"`
	Temperature float64 `json:"temperature"`
}
type Point struct {
	BootID   string  `json:"boot,omitempty"`
	Pressure float64 `json:"pressure"`
	SwapIn   float64 `json:"swapIn"`
	SwapOut  float64 `json:"swapOut"`
	Samples  int     `json:"samples,omitempty"`
	Time     int64   `json:"time"`
	CPU      float64 `json:"cpu"`
	Memory   float64 `json:"memory"`
	RX       float64 `json:"rx"`
	TX       float64 `json:"tx"`
	Read     float64 `json:"read"`
	Write    float64 `json:"write"`
}
type Snapshot struct {
	Boot              string     `json:"boot"`
	Groups            []Group    `json:"groups"`
	Workloads         []Workload `json:"workloads"`
	MemoryPressure    Pressure   `json:"memoryPressure"`
	Alerts            []Alert    `json:"alerts"`
	DockerAvailable   bool       `json:"dockerAvailable"`
	ServicesAvailable bool       `json:"servicesAvailable"`
	Point
	Host        string    `json:"host"`
	Kernel      string    `json:"kernel"`
	Model       string    `json:"model"`
	Uptime      float64   `json:"uptime"`
	Load        string    `json:"load"`
	Cores       []float64 `json:"cores"`
	Total       uint64    `json:"total"`
	Used        uint64    `json:"used"`
	Available   uint64    `json:"available"`
	Cached      uint64    `json:"cached"`
	Buffers     uint64    `json:"buffers"`
	SwapTotal   uint64    `json:"swapTotal"`
	SwapUsed    uint64    `json:"swapUsed"`
	Processes   []Process `json:"processes"`
	Disks       []Disk    `json:"disks"`
	Networks    []Network `json:"networks"`
	Sensors     []Sensor  `json:"sensors"`
	GPUs        []GPU     `json:"gpus"`
	Signals     bool      `json:"signals"`
	CollectorMS float64   `json:"collectorMs"`
}
type Collector struct {
	icons                                             *IconCatalog
	archive                                           Archive
	boot                                              string
	lastUsage                                         int64
	metaAt                                            time.Time
	workAt                                            time.Time
	workloadList                                      []Workload
	dockerAvailable                                   bool
	servicesAvailable                                 bool
	swap                                              [2]uint64
	alerts                                            *AlertManager
	mu                                                sync.RWMutex
	current                                           Snapshot
	history                                           []Point
	cpus                                              []CPUTime
	procs                                             map[int]Process
	net                                               map[string][2]uint64
	disk                                              [2]uint64
	last                                              time.Time
	users                                             map[int]string
	gpu                                               []GPU
	gpuMem                                            map[int]uint64
	gpuUsage                                          map[int]float64
	gpuAt                                             time.Time
	host, model, kernel, procRoot, stateDir, hostRoot string
	signals                                           bool
}

func read(path string) string  { b, _ := os.ReadFile(path); return strings.TrimSpace(string(b)) }
func num(s string) uint64      { v, _ := strconv.ParseUint(s, 10, 64); return v }
func realnum(s string) float64 { v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64); return v }
func parseStat(s string) (Process, error) {
	left, right := strings.Index(s, "("), strings.LastIndex(s, ")")
	if left < 1 || right <= left {
		return Process{}, fmt.Errorf("invalid process stat")
	}
	f := strings.Fields(s[right+1:])
	if len(f) < 22 {
		return Process{}, fmt.Errorf("short process stat")
	}
	return Process{PID: int(num(strings.TrimSpace(s[:left]))), Name: s[left+1 : right], State: f[0], PPID: int(num(f[1])), Ticks: num(f[11]) + num(f[12]), Threads: int(num(f[17])), Start: num(f[19]), RAM: num(f[21]) * uint64(os.Getpagesize())}, nil
}
func (c *Collector) process(pid int) (Process, error) {
	base := filepath.Join(c.procRoot, strconv.Itoa(pid))
	p, e := parseStat(read(base + "/stat"))
	if e != nil {
		return p, e
	}
	p.UID = -1
	for _, line := range strings.Split(read(base+"/status"), "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && f[0] == "Uid:" {
			p.UID = int(num(f[1]))
			break
		}
	}
	p.User = strconv.Itoa(p.UID)
	if u, ok := c.users[p.UID]; ok {
		p.User = u
	} else if u, e := user.LookupId(p.User); e == nil {
		p.User = u.Username
		c.users[p.UID] = u.Username
	}
	return p, nil
}
func newCollector(state string, signals bool) *Collector {
	host, _ := os.Hostname()
	c := &Collector{host: host, kernel: read("/proc/sys/kernel/osrelease"), procRoot: "/proc", hostRoot: "/", stateDir: state, signals: signals, procs: map[int]Process{}, net: map[string][2]uint64{}, users: map[int]string{}}
	for _, line := range strings.Split(read("/proc/cpuinfo"), "\n") {
		if strings.HasPrefix(line, "model name") {
			c.model = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			break
		}
	}
	b, _ := os.ReadFile(filepath.Join(state, "history.json"))
	_ = json.Unmarshal(b, &c.history)
	if len(c.history) > 1800 {
		c.history = c.history[len(c.history)-1800:]
	}
	c.boot = read("/proc/sys/kernel/random/boot_id")
	c.alerts = newAlerts(state)
	c.loadArchive()
	if len(c.archive.Minutes) == 0 {
		for _, point := range c.history {
			c.archive.Minutes = appendPoint(c.archive.Minutes, point, 60000, 10080)
			c.archive.Hours = appendPoint(c.archive.Hours, point, 3600000, 2160)
		}
	}
	return c
}
func cpuTimes(root string) []CPUTime {
	var out []CPUTime
	for _, l := range strings.Split(read(root+"/stat"), "\n") {
		f := strings.Fields(l)
		if len(f) < 5 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		var t CPUTime
		for i := 1; i < len(f) && i <= 8; i++ {
			t.Total += num(f[i])
		}
		t.Idle = num(f[4])
		if len(f) > 5 {
			t.Idle += num(f[5])
		}
		out = append(out, t)
	}
	return out
}
func (c *Collector) sample() {
	began := time.Now()
	dt := began.Sub(c.last).Seconds()
	if c.last.IsZero() {
		dt = 2
	}
	s := Snapshot{Host: c.host, Kernel: c.kernel, Model: c.model, Signals: c.signals, Processes: []Process{}, Disks: []Disk{}, Networks: []Network{}, Sensors: []Sensor{}, GPUs: []GPU{}}
	s.Time = began.UnixMilli()
	s.Point.BootID = c.boot
	loads := strings.Fields(read(c.procRoot + "/loadavg"))
	if len(loads) >= 3 {
		s.Load = strings.Join(loads[:3], "  ")
	}
	s.Uptime = realnum(strings.Split(read(c.procRoot+"/uptime"), " ")[0])
	times := cpuTimes(c.procRoot)
	var totalDelta uint64
	for i, t := range times {
		v := 0.0
		if i < len(c.cpus) && t.Total > c.cpus[i].Total {
			d := t.Total - c.cpus[i].Total
			idle := t.Idle - c.cpus[i].Idle
			if idle <= d {
				v = 100 * float64(d-idle) / float64(d)
			}
			if i == 0 {
				totalDelta = d
			}
		}
		if i == 0 {
			s.CPU = v
		} else {
			s.Cores = append(s.Cores, v)
		}
	}
	mem := map[string]uint64{}
	for _, l := range strings.Split(read(c.procRoot+"/meminfo"), "\n") {
		f := strings.Fields(l)
		if len(f) > 1 {
			mem[strings.TrimSuffix(f[0], ":")] = num(f[1]) * 1024
		}
	}
	s.Total = mem["MemTotal"]
	s.Available = mem["MemAvailable"]
	s.Used = s.Total - s.Available
	s.Cached = mem["Cached"] + mem["SReclaimable"]
	s.Buffers = mem["Buffers"]
	s.SwapTotal = mem["SwapTotal"]
	s.SwapUsed = s.SwapTotal - mem["SwapFree"]
	if s.Total > 0 {
		s.Memory = 100 * float64(s.Used) / float64(s.Total)
	}
	c.readGPU(began)
	entries, _ := os.ReadDir(c.procRoot)
	next := map[int]Process{}
	for _, ent := range entries {
		pid, e := strconv.Atoi(ent.Name())
		if e != nil {
			continue
		}
		p, e := c.process(pid)
		if e != nil {
			continue
		}
		if old, ok := c.procs[pid]; ok && old.Start == p.Start && p.Ticks >= old.Ticks && totalDelta > 0 {
			p.CPU = 100 * float64(p.Ticks-old.Ticks) * float64(len(s.Cores)) / float64(totalDelta)
		}
		if m, ok := c.gpuMem[pid]; ok {
			v := m
			p.GPUMemory = &v
		}
		if u, ok := c.gpuUsage[pid]; ok {
			v := u
			p.GPUUsage = &v
		}
		c.metadata(&p)
		next[pid] = p
		s.Processes = append(s.Processes, p)
	}
	for _, l := range strings.Split(read(c.procRoot+"/net/dev"), "\n") {
		parts := strings.SplitN(l, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		f := strings.Fields(parts[1])
		if len(f) < 16 {
			continue
		}
		v := [2]uint64{num(f[0]), num(f[8])}
		n := Network{Name: name, Received: v[0], Sent: v[1]}
		if old, ok := c.net[name]; ok && v[0] >= old[0] && v[1] >= old[1] {
			n.RX = float64(v[0]-old[0]) / dt
			n.TX = float64(v[1]-old[1]) / dt
		}
		c.net[name] = v
		s.Networks = append(s.Networks, n)
		if name != "lo" {
			s.RX += n.RX
			s.TX += n.TX
		}
	}
	var disk [2]uint64
	for _, l := range strings.Split(read(c.procRoot+"/diskstats"), "\n") {
		f := strings.Fields(l)
		if len(f) < 14 {
			continue
		}
		name := f[2]
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") {
			continue
		}
		if _, e := os.Stat("/sys/block/" + name); e != nil {
			continue
		}
		disk[0] += num(f[5]) * 512
		disk[1] += num(f[9]) * 512
	}
	if !c.last.IsZero() && disk[0] >= c.disk[0] && disk[1] >= c.disk[1] {
		s.Read = float64(disk[0]-c.disk[0]) / dt
		s.Write = float64(disk[1]-c.disk[1]) / dt
	}
	seen := map[string]bool{}
	mountFile := c.procRoot + "/mounts"
	if c.hostRoot != "/" {
		mountFile = c.procRoot + "/1/mounts"
	}
	for _, l := range strings.Split(read(mountFile), "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || (!strings.HasPrefix(f[0], "/dev/") && f[2] != "overlay") {
			continue
		}
		mount := strings.ReplaceAll(f[1], `\040`, " ")
		if seen[f[0]] {
			continue
		}
		var st syscall.Statfs_t
		if syscall.Statfs(filepath.Join(c.hostRoot, mount), &st) != nil {
			continue
		}
		seen[f[0]] = true
		s.Disks = append(s.Disks, Disk{f[0], mount, f[2], st.Blocks * uint64(st.Bsize), (st.Blocks - st.Bfree) * uint64(st.Bsize)})
	}
	paths, _ := filepath.Glob("/sys/class/hwmon/hwmon*/temp*_input")
	for _, p := range paths {
		v := realnum(read(p)) / 1000
		if v <= 0 || v > 150 {
			continue
		}
		label := read(strings.TrimSuffix(p, "_input") + "_label")
		if label == "" {
			label = filepath.Base(strings.TrimSuffix(p, "_input"))
		}
		s.Sensors = append(s.Sensors, Sensor{read(filepath.Dir(p)+"/name") + " / " + label, v})
	}
	s.GPUs = c.gpu
	c.enrich(&s)
	c.decorateApplications(&s)
	s.Alerts = c.alerts.evaluate(s)
	if began.Sub(c.metaAt) >= 30*time.Second {
		c.metaAt = began
	}
	s.CollectorMS = float64(time.Since(began).Microseconds()) / 1000
	c.cpus = times
	c.procs = next
	c.disk = disk
	c.last = began
	c.mu.Lock()
	c.current = s
	c.record(s)
	c.history = append(c.history, s.Point)
	if len(c.history) > 1800 {
		copy(c.history, c.history[len(c.history)-1800:])
		c.history = c.history[:1800]
	}
	c.mu.Unlock()
}
func (c *Collector) readGPU(now time.Time) {
	if now.Sub(c.gpuAt) < 10*time.Second {
		return
	}
	c.gpuAt = now
	c.gpu = []GPU{}
	c.gpuMem = map[int]uint64{}
	c.gpuUsage = map[int]float64{}
	if _, e := exec.LookPath("nvidia-smi"); e != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu", "--format=csv,noheader,nounits").Output()
	if e != nil {
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		f := strings.Split(scanner.Text(), ",")
		if len(f) == 5 {
			c.gpu = append(c.gpu, GPU{strings.TrimSpace(f[0]), realnum(f[1]), uint64(realnum(f[2]) * 1048576), uint64(realnum(f[3]) * 1048576), realnum(f[4])})
		}
	}
	b, e = exec.CommandContext(ctx, "nvidia-smi", "--query-compute-apps=pid,used_gpu_memory", "--format=csv,noheader,nounits").Output()
	if e == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Split(l, ",")
			if len(f) == 2 {
				c.gpuMem[int(num(strings.TrimSpace(f[0])))] += uint64(realnum(f[1]) * 1048576)
			}
		}
	}
	c.readGPUProcesses(ctx)
}
func (c *Collector) save() {
	c.saveArchive()
	c.mu.RLock()
	b, e := json.Marshal(c.history)
	c.mu.RUnlock()
	if e == nil {
		p := filepath.Join(c.stateDir, "history.json")
		if os.WriteFile(p+".tmp", b, 0600) == nil {
			_ = os.Rename(p+".tmp", p)
		}
	}
}

func (c *Collector) readGPUProcesses(ctx context.Context) {
	b, e := exec.CommandContext(ctx, "nvidia-smi", "pmon", "-c", "1", "-s", "um").Output()
	if e != nil {
		return
	}
	fb := -1
	memory := map[int]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#")))
		if len(f) < 5 {
			continue
		}
		if f[0] == "gpu" && f[1] == "pid" {
			for i, k := range f {
				if k == "fb" {
					fb = i
				}
			}
			continue
		}
		pid, e := strconv.Atoi(f[1])
		if e != nil || pid < 1 {
			continue
		}
		if f[3] != "-" {
			if u, e := strconv.ParseFloat(f[3], 64); e == nil {
				c.gpuUsage[pid] += u
			}
		}
		if fb >= 0 && len(f) > fb && f[fb] != "-" {
			memory[pid] += num(f[fb]) * 1048576
		}
	}
	for pid, m := range memory {
		c.gpuMem[pid] = m
	}
}
