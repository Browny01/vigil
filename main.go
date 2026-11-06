package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/*
var assets embed.FS

type server struct {
	c        *Collector
	password [32]byte
	mu       sync.Mutex
	sessions map[string]time.Time
	attempts map[string][]time.Time
	secure   bool
}

func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (s *server) authenticated(r *http.Request) bool {
	cookie, e := r.Cookie("vigil_session")
	if e != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.sessions[cookie.Value]
	return ok && time.Now().Before(expiry)
}
func safeOrigin(r *http.Request) bool {
	if r.Header.Get("X-Vigil-Request") != "1" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	return e == nil && u.Host == r.Host
}
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		if !safeOrigin(r) {
			http.Error(w, "Invalid origin", 403)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		now := time.Now()
		s.mu.Lock()
		recent := []time.Time{}
		for _, t := range s.attempts[ip] {
			if now.Sub(t) < time.Minute {
				recent = append(recent, t)
			}
		}
		blocked := len(recent) >= 5
		if len(s.attempts) > 1024 {
			s.attempts = map[string][]time.Time{}
		}
		s.attempts[ip] = append(recent, now)
		s.mu.Unlock()
		if blocked {
			http.Error(w, "Too many attempts; try again in a minute", 429)
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil {
			http.Error(w, "Invalid request", 400)
			return
		}
		hash := sha256.Sum256([]byte(body.Password))
		if subtle.ConstantTimeCompare(hash[:], s.password[:]) != 1 {
			http.Error(w, "Incorrect password", 401)
			return
		}
		id := token()
		s.mu.Lock()
		for k, t := range s.sessions {
			if now.After(t) {
				delete(s.sessions, k)
			}
		}
		if len(s.sessions) >= 128 {
			s.mu.Unlock()
			http.Error(w, "Too many active sessions", 429)
			return
		}
		s.sessions[id] = now.Add(24 * time.Hour)
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "vigil_session", Value: id, Path: "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: 86400})
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		if !safeOrigin(r) {
			http.Error(w, "Invalid origin", 403)
			return
		}
		if c, e := r.Cookie("vigil_session"); e == nil {
			s.mu.Lock()
			delete(s.sessions, c.Value)
			s.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "vigil_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode})
		writeJSON(w, map[string]bool{"ok": true})
	})
	api := func(pattern string, fn http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if !s.authenticated(r) {
				http.Error(w, "Authentication required", 401)
				return
			}
			fn(w, r)
		})
	}
	api("GET /api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		s.c.mu.RLock()
		defer s.c.mu.RUnlock()
		writeJSON(w, s.c.current)
	})
	api("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.c.historyRange(rangeMS(r, 3600000, 90*86400000)))
	})
	s.monitorRoutes(api)
	api("GET /api/icons/{id}", s.iconHandler)

	api("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Accel-Buffering", "no")
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			if !s.authenticated(r) {
				return
			}
			s.c.mu.RLock()
			snapshot := s.c.current
			s.c.mu.RUnlock()
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(8 * time.Second))
			b, _ := json.Marshal(snapshot)
			if _, e := fmt.Fprintf(w, "data: %s\n\n", b); e != nil {
				return
			}
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-t.C:
			}
		}
	})
	api("GET /api/process/{pid}", func(w http.ResponseWriter, r *http.Request) {
		pid, e := strconv.Atoi(r.PathValue("pid"))
		if e != nil || pid < 1 {
			http.Error(w, "Invalid PID", 400)
			return
		}
		base := filepath.Join(s.c.procRoot, strconv.Itoa(pid))
		p, e := parseStat(read(base + "/stat"))
		if e != nil {
			http.Error(w, "Process has exited", 404)
			return
		}
		cmd := strings.ReplaceAll(read(base+"/cmdline"), "\x00", " ")
		exe, _ := os.Readlink(base + "/exe")
		cwd, _ := os.Readlink(base + "/cwd")
		fds, fdErr := os.ReadDir(base + "/fd")
		writeJSON(w, map[string]any{"process": p, "command": cmd, "executable": exe, "cwd": cwd, "status": read(base + "/status"), "io": read(base + "/io"), "fds": len(fds), "restricted": fdErr != nil})
	})
	api("POST /api/process/{pid}/signal", func(w http.ResponseWriter, r *http.Request) {
		if !safeOrigin(r) {
			http.Error(w, "Invalid origin", 403)
			return
		}
		if !s.c.signals {
			http.Error(w, "Process control is disabled", 403)
			return
		}
		pid, e := strconv.Atoi(r.PathValue("pid"))
		if e != nil || pid <= 1 {
			http.Error(w, "Invalid PID", 400)
			return
		}
		var body struct {
			Start  uint64 `json:"start"`
			Signal string `json:"signal"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body) != nil {
			http.Error(w, "Invalid request", 400)
			return
		}
		sig := syscall.SIGTERM
		if body.Signal == "KILL" {
			sig = syscall.SIGKILL
		} else if body.Signal != "TERM" {
			http.Error(w, "Unsupported signal", 400)
			return
		}
		if e := signalProcess(s.c, pid, body.Start, sig); e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		log.Printf("process signal: pid=%d start=%d signal=%s", pid, body.Start, body.Signal)
		writeJSON(w, map[string]bool{"ok": true})
	})
	web, _ := fs.Sub(assets, "web")
	mux.Handle("GET /", http.FileServer(http.FS(web)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		mux.ServeHTTP(w, r)
	})
}
func signalProcess(c *Collector, pid int, start uint64, sig syscall.Signal) error {
	for ancestor := os.Getpid(); ancestor > 1; {
		if ancestor == pid {
			return fmt.Errorf("Vigil and its ancestors are protected")
		}
		p, e := parseStat(read(fmt.Sprintf("/proc/%d/stat", ancestor)))
		if e != nil {
			break
		}
		ancestor = p.PPID
	}
	// pidfds pin process identity across the check and the signal (Linux 5.3+).
	fd, _, errno := syscall.Syscall(434, uintptr(pid), 0, 0)
	if errno != 0 {
		return fmt.Errorf("cannot open process handle: %s", errno)
	}
	defer syscall.Close(int(fd))
	p, e := parseStat(read(filepath.Join(c.procRoot, strconv.Itoa(pid), "stat")))
	if e != nil || p.Start != start {
		return fmt.Errorf("process exited or PID was reused; select it again")
	}
	var stat syscall.Stat_t
	if syscall.Stat(filepath.Join(c.procRoot, strconv.Itoa(pid)), &stat) != nil || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("only processes owned by Vigil's user can be terminated")
	}
	_, _, errno = syscall.Syscall6(424, fd, uintptr(sig), 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("signal refused: %s", errno)
	}
	return nil
}
func main() {
	addr := flag.String("listen", "127.0.0.1:9120", "HTTP listen address")
	home, _ := os.UserHomeDir()
	state := flag.String("state", filepath.Join(home, ".local/state/vigil"), "private state directory")
	signals := flag.Bool("allow-signals", false, "allow terminating processes owned by this user")
	procRoot := flag.String("proc-root", "/proc", "procfs path (for container host monitoring)")
	hostRoot := flag.String("host-root", "/", "host filesystem mount prefix")
	secure := flag.Bool("secure-cookie", false, "require HTTPS for session cookies (TLS proxy)")
	showPassword := flag.Bool("show-password", false, "print the stored login password and exit")
	flag.Parse()
	if *showPassword {
		b, e := os.ReadFile(filepath.Join(*state, "password"))
		if e != nil {
			log.Fatal(e)
		}
		fmt.Print(string(b))
		return
	}
	if *signals && *procRoot != "/proc" {
		log.Fatal("process control requires the native /proc namespace")
	}
	if _, e := os.Stat(filepath.Join(*procRoot, "stat")); e != nil {
		log.Fatal("procfs is not accessible: ", e)
	}
	if e := os.MkdirAll(*state, 0700); e != nil {
		log.Fatal(e)
	}
	if e := os.Chmod(*state, 0700); e != nil {
		log.Fatal(e)
	}
	password := os.Getenv("VIGIL_PASSWORD")
	if password == "" {
		path := filepath.Join(*state, "password")
		b, e := os.ReadFile(path)
		if os.IsNotExist(e) {
			password = token()
			e = os.WriteFile(path, []byte(password+"\n"), 0600)
		} else {
			password = strings.TrimSpace(string(b))
		}
		if e != nil {
			log.Fatal(e)
		}
		log.Printf("Login password is stored in %s", path)
	}
	if len(password) < 16 {
		log.Fatal("VIGIL_PASSWORD must contain at least 16 characters")
	}
	c := newCollector(*state, *signals)
	c.icons = newIconCatalog()
	c.procRoot = *procRoot
	c.hostRoot = *hostRoot
	c.kernel = read(filepath.Join(*procRoot, "sys/kernel/osrelease"))
	c.alerts.startWebhook(os.Getenv("VIGIL_ALERT_WEBHOOK"))
	c.sample()
	s := &server{c: c, password: sha256.Sum256([]byte(password)), sessions: map[string]time.Time{}, attempts: map[string][]time.Time{}, secure: *secure}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		n := 0
		for {
			select {
			case <-tick.C:
				c.sample()
				n++
				if n%30 == 0 {
					c.save()
				}
			case <-stop:
				c.save()
				os.Exit(0)
			}
		}
	}()
	srv := &http.Server{Addr: *addr, Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	log.Printf("Vigil listening at http://%s (process control: %t)", *addr, *signals)
	log.Fatal(srv.ListenAndServe())
}
