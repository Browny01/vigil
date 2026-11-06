<p align="center"><img src="web/logo.png" width="100" alt="Vigil logo"></p>
<h1 align="center">Vigil</h1>
<p align="center">A process-first Linux system monitor. Self-hosted. One binary.</p>
<p align="center"><a href="https://github.com/Browny01/vigil/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Browny01/vigil/actions/workflows/ci.yml/badge.svg"></a> <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a></p>

Vigil brings detailed process monitoring to the browser: expandable application groups, per-process history, memory pressure, hardware statistics, service and container awareness, and useful alerts. A compact interface pairs dot-matrix activity graphs with a dense process table, installed application icons, and light/dark appearance that defaults to your system.

The backend uses Go's standard library. The frontend is embedded HTML, CSS, and JavaScript—no frontend framework, database, CDN, or telemetry. Install it on the **Linux computer you want to monitor**, then open it from any modern browser, including a Mac or phone.

## Quick start

### Download a binary

Download the matching Linux `amd64` or `arm64` archive and `SHA256SUMS` from [Releases](https://github.com/Browny01/vigil/releases). Extract the archive, verify its checksum, then run:

```sh
./vigil
```

Open **http://127.0.0.1:9120**. Read the generated password in another terminal:

```sh
cat ~/.local/state/vigil/password
```

Monitoring is read-only by default. To allow confirmed termination of processes owned by Vigil's user:

```sh
./vigil -allow-signals
```

### Build from source

Requires Linux and Go 1.24 or newer.

```sh
git clone https://github.com/Browny01/vigil.git
cd vigil
make build
./bin/vigil
```

### Docker Compose

```sh
git clone https://github.com/Browny01/vigil.git
cd vigil
docker compose up -d --build
docker compose exec vigil /vigil -state=/data -show-password
```

Open http://127.0.0.1:9120. Compose builds a minimal, non-root image with a read-only root filesystem, dropped capabilities, read-only host mounts, and persistent state in a named volume. It uses Linux host networking and mounts host procfs to inspect host processes. No privileged container or Docker socket is required.

**The native binary provides the fullest experience.** The minimal container lacks `nvidia-smi`, `systemctl`, the Docker CLI, and desktop icons. It can show host processes and cgroup ownership IDs, but cannot provide GPU telemetry, full service/container metadata, or host process controls. Host filesystem/procfs permissions can restrict details in either installation.

## What you can monitor

- **Processes and applications:** CPU, RSS, GPU metrics where available, threads, PID, owner and state. Group related processes, search, filter, sort, inspect command lines and file descriptors, and open resource history.
- **Hardware:** per-core CPU, load, uptime, memory breakdown, disk capacity and I/O, network interfaces, hwmon temperatures, and NVIDIA utilization/VRAM/temperature when the host has `nvidia-smi`.
- **Memory pressure:** Linux PSI stall readings plus real swap-in/swap-out rates. Occupied swap alone does not mean the host is actively swapping.
- **Services and containers:** system/user service ownership, state and automatic restart counts; Docker names, images, health and associated process resource totals. Optional CLI discovery runs every 30 seconds with bounded timeouts.
- **History:** interactive dot graphs, current/average/peak values, adaptive scales, keyboard scrubbing and time-range controls. Application histories follow stable identities across observed restarts; process histories distinguish boot ID, PID and start time.
- **Alerts:** configurable sustained CPU, memory, PSI, swap, disk, temperature and unhealthy workload rules; acknowledgment, recovery tracking, browser notifications and an optional HTTPS webhook.
- **Appearance:** system-default light/dark mode, a sun/moon toggle, responsive views, custom keyboard-accessible menus, and configurable/rearrangeable metric cards.

CPU uses 100% per logical core for individual processes; total host CPU uses 0–100%. Group RSS can count shared pages more than once. Memory cache overlaps reclaimable/available memory. Virtual interfaces can count forwarded network traffic at multiple layers; aggregate physical disk I/O can count RAID members separately. Missing metrics are shown as unavailable, never replaced with example data.

## Remote access

Each installation has its **own password and private state**. Vigil binds to loopback by default. A simple private connection from another computer is an SSH tunnel:

```sh
ssh -N -L 9120:127.0.0.1:9120 user@your-linux-host
```

Then open http://127.0.0.1:9120 on that computer. For a permanent HTTPS address, put Vigil behind your preferred TLS reverse proxy or tunnel and start it with `-secure-cookie`. Preserve the original `Host` header, disable buffering for `/api/events`, and allow long-lived streaming responses. Do not expose plain HTTP on an untrusted network.

Vigil protects metrics and actions with password authentication, random HttpOnly/SameSite cookies, login throttling, same-origin POST validation and a content security policy. Anyone with the password can inspect sensitive process information and use enabled controls. This is a **single-administrator self-hosted application**, not a multi-tenant service. Multi-user accounts and roles are not implemented.

## Configuration

Run `./vigil -help` for all options.

| Option | Default | Purpose |
| --- | --- | --- |
| `-listen` | `127.0.0.1:9120` | HTTP address |
| `-state` | `~/.local/state/vigil` | Private credentials, history and alerts |
| `-allow-signals` | `false` | Permit SIGTERM/SIGKILL for this user's processes |
| `-secure-cookie` | `false` | Require HTTPS for session cookies |
| `-show-password` | `false` | Print the stored password and exit |
| `-proc-root` | `/proc` | Alternate procfs mount for read-only container monitoring |
| `-host-root` | `/` | Host filesystem prefix for partition capacity |

`VIGIL_PASSWORD` overrides the generated password; use a strong random value of at least 16 characters. `VIGIL_ALERT_WEBHOOK` optionally sets an administrator-controlled HTTPS endpoint for JSON alert activation/recovery events. Keep environment files private and out of version control. Restarting invalidates active sessions. Generated state uses directory mode 0700 and file mode 0600.

### Run at login with systemd

```sh
install -Dm755 bin/vigil ~/.local/bin/vigil
install -Dm644 packaging/vigil.service ~/.config/systemd/user/vigil.service
systemctl --user daemon-reload
systemctl --user enable --now vigil
```

For a downloaded release, replace `bin/vigil` with `./vigil`. The sample service is read-only; add flags via a systemd override if needed. View logs with `journalctl --user -u vigil`. Starting a user service at boot without logging in requires user lingering, configured by the administrator.

## History and alerts

| Data | Resolution | Retention |
| --- | --- | --- |
| Recent system | 2 seconds | 1 hour |
| System summaries | 1 minute | 7 days |
| System summaries | 1 hour | 90 days |
| Process instance | 10 seconds | 30 minutes |
| Recent application | 10 seconds | 30 minutes |
| Application summaries | 1 minute | 24 hours |
| Application summaries | 1 hour | 7 days |

Storage and memory are bounded to 512 process identities and 128 application identities, prioritizing active high-RSS entries. Every readable process remains visible in the live list. Summary readings are averages, not instantaneous peaks. Short-lived processes can be missed between samples. History is saved every minute and on orderly shutdown; abrupt power loss can lose the latest minute. Application leader changes may indicate restarts or main-process replacements.

Alert defaults cover CPU ≥90% and memory ≥95% for 60 seconds, memory stalls ≥10%, swap I/O ≥1 MiB/s and temperature ≥85°C for 30 seconds, filesystem usage ≥90% for 60 seconds, and unhealthy workloads for 30 seconds. Edit them in **Alerts → Configure alerts**. The latest 200 events persist locally.

Browser notifications require permission and an open page. A configured webhook can deliver while the browser is closed; it receives `{ "source": "Vigil", "alert": { ... } }`. Delivery uses a bounded queue, five-second timeout and no redirects; failed requests are logged but not automatically retried. A powered-off host cannot send its own offline alert—use an external checker for that.

## Development

```sh
make test                 # Go race-enabled tests; includes a disposable-child signal test
make build
go vet ./...
for file in web/*.js; do node --check "$file"; done
```

Optional browser tests require Node.js and Playwright, **only for development**:

```sh
npm install --no-save --package-lock=false playwright
npx playwright install chromium
# Against a running test instance, not a production monitoring session:
VIGIL_URL=http://127.0.0.1:9120 node tests/reference-ui.cjs
```

Set `VIGIL_PASSWORD_FILE` if the test instance uses a non-default state directory. `PLAYWRIGHT_PATH` and `CHROMIUM_PATH` can point to existing development installations. Tests write screenshots to ignored `artifacts/`; screenshots may contain private process names. Other browser scripts exercise alerts and may temporarily modify test-instance settings. `tests/browser.cjs` also terminates a disposable child process and requires the test instance to use `-allow-signals`.

CI runs Go tests, vet, JavaScript syntax checks, and builds Linux amd64/arm64 binaries. Contributions should include a focused check and avoid adding runtime dependencies unless the benefit justifies them. Never submit credentials, local process snapshots, private hostnames, or generated monitoring state.

## Scope and license

Linux first. NVIDIA GPU metrics depend on driver support; per-process graphics metrics can be unavailable. Application icons come from installed desktop entries and icon themes, with neutral fallbacks. Systemd and Docker are optional. Windows/macOS host collectors, multi-host agents, external databases, user roles and externally hosted offline checks are not included.

Vigil's code and supplied branding are available under the [MIT license](LICENSE). Discovered third-party application icons remain the property of their respective owners and are not bundled in the repository.
