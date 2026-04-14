# pmon — Port Monitor

A Windows terminal UI for monitoring TCP connection state counts over time.
Useful for diagnosing port exhaustion on busy servers.

## What it tracks

| State | Concern |
|---|---|
| `ESTABLISHED` | Active connections |
| `TIME_WAIT` | Sockets waiting to close — high counts indicate port exhaustion risk |
| `CLOSE_WAIT` | Remote side closed but local app hasn't — usually a bug in the application |

## Usage

```
pmon.exe
```

No arguments. Press `q` or `Esc` to quit.

| Key | Action |
|---|---|
| `q` / `Esc` | Quit |
| `↑` / `k` | Scroll process list up |
| `↓` / `j` | Scroll process list down |

## Features

- Samples `netstat -ano` every **10 seconds** in a background thread (UI stays responsive)
- Keeps up to **1 hour** of history (360 samples) displayed as braille line charts
- Title bar shows current values with **delta** from the previous sample
- Chart titles show **peak** value seen in the current session
- Process table sorted by total connection count, color-coded by severity:
  - **Red** — process has ≥ 5 `CLOSE_WAIT` connections
  - **Yellow** — process has ≥ 50 `TIME_WAIT` connections

## Build

Requires [Rust](https://rustup.rs/) (stable, 2024 edition).

```powershell
# Debug build
cargo build

# Release build (smaller, faster)
cargo build --release
# Binary: target\release\pmon.exe
```

## Requirements

- Windows Server (any version with `netstat.exe`)
- Terminal with Unicode support (Windows Terminal recommended for best braille rendering)
