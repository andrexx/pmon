use std::{
    cmp::Reverse,
    collections::{HashMap, VecDeque},
    io,
    process::Command,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::Span,
    widgets::{Axis, Block, Chart, Dataset, GraphType, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use sysinfo::{Pid, ProcessesToUpdate, System};

// ─── Constants ───────────────────────────────────────────────────────────────

const COLLECT_INTERVAL_SECS: u64 = 10;
const MAX_HISTORY: usize = 360; // 10s × 360 = 1 hour

// ─── Data types ──────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct Snapshot {
    elapsed_secs: f64,
    established: u64,
    time_wait: u64,
    close_wait: u64,
}

#[derive(Clone)]
struct ProcInfo {
    pid: u32,
    name: String,
    established: u64,
    time_wait: u64,
    close_wait: u64,
}

impl ProcInfo {
    fn total(&self) -> u64 {
        self.established + self.time_wait + self.close_wait
    }
}

enum CollectorMsg {
    Data(Snapshot, Vec<ProcInfo>),
}

// ─── Collector (background thread) ───────────────────────────────────────────

/// Parse `netstat -ano` output on Windows.
/// Format: Proto  LocalAddr  ForeignAddr  State  PID
fn collect_once(sys: &mut System, elapsed_secs: f64) -> (Snapshot, Vec<ProcInfo>) {
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let output = match Command::new("netstat").args(["-ano"]).output() {
        Ok(o) => o,
        Err(_) => return (Snapshot { elapsed_secs, ..Default::default() }, Vec::new()),
    };

    let text = String::from_utf8_lossy(&output.stdout);

    let mut snap = Snapshot { elapsed_secs, ..Default::default() };
    // pid -> (established, time_wait, close_wait)
    let mut pid_map: HashMap<u32, (u64, u64, u64)> = HashMap::new();

    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // We only care about TCP rows: TCP  local  foreign  STATE  PID
        if cols.len() < 5 || cols[0] != "TCP" {
            continue;
        }
        let state = cols[3];
        let pid: u32 = cols[4].parse().unwrap_or(0);
        let e = pid_map.entry(pid).or_insert((0, 0, 0));

        match state {
            "ESTABLISHED" => {
                snap.established += 1;
                e.0 += 1;
            }
            "TIME_WAIT" => {
                snap.time_wait += 1;
                e.1 += 1;
            }
            "CLOSE_WAIT" => {
                snap.close_wait += 1;
                e.2 += 1;
            }
            _ => {}
        }
    }

    let mut procs: Vec<ProcInfo> = pid_map
        .into_iter()
        .map(|(pid, (est, tw, cw))| {
            let name = sys
                .process(Pid::from(pid as usize))
                .map(|p| p.name().to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("({pid})"));
            ProcInfo { pid, name, established: est, time_wait: tw, close_wait: cw }
        })
        .collect();

    procs.sort_by_key(|p| Reverse(p.total()));
    (snap, procs)
}

fn spawn_collector(tx: mpsc::Sender<CollectorMsg>, start: Instant) {
    thread::spawn(move || {
        let mut sys = System::new();
        loop {
            let elapsed = start.elapsed().as_secs_f64();
            let (snap, procs) = collect_once(&mut sys, elapsed);
            if tx.send(CollectorMsg::Data(snap, procs)).is_err() {
                break; // main thread exited
            }
            thread::sleep(Duration::from_secs(COLLECT_INTERVAL_SECS));
        }
    });
}

// ─── App state ───────────────────────────────────────────────────────────────

struct App {
    history: VecDeque<Snapshot>,
    procs: Vec<ProcInfo>,
    table_state: TableState,
    last_collect: Instant,
    collecting: bool,
    rx: mpsc::Receiver<CollectorMsg>,
}

impl App {
    fn new(rx: mpsc::Receiver<CollectorMsg>) -> Self {
        App {
            history: VecDeque::with_capacity(MAX_HISTORY + 1),
            procs: Vec::new(),
            table_state: TableState::default(),
            last_collect: Instant::now(),
            collecting: true,
            rx,
        }
    }

    /// Drain any pending messages from the collector thread.
    fn poll(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                CollectorMsg::Data(snap, procs) => {
                    self.collecting = false;
                    if self.history.len() >= MAX_HISTORY {
                        self.history.pop_front();
                    }
                    self.history.push_back(snap);
                    self.procs = procs;
                    self.last_collect = Instant::now();
                }
            }
        }
    }

    fn current(&self) -> Snapshot {
        self.history.back().cloned().unwrap_or_default()
    }

    fn prev(&self) -> Option<&Snapshot> {
        let len = self.history.len();
        if len >= 2 { self.history.get(len - 2) } else { None }
    }

    fn series(&self, f: fn(&Snapshot) -> u64) -> Vec<(f64, f64)> {
        self.history.iter().map(|s| (s.elapsed_secs, f(s) as f64)).collect()
    }

    fn history_minutes(&self) -> u64 {
        (self.history.len() as u64 * COLLECT_INTERVAL_SECS) / 60
    }

    fn secs_to_next(&self) -> u64 {
        Duration::from_secs(COLLECT_INTERVAL_SECS)
            .checked_sub(self.last_collect.elapsed())
            .unwrap_or_default()
            .as_secs()
    }

    fn scroll_down(&mut self) {
        let max = self.procs.len().saturating_sub(1);
        let i = self.table_state.selected().map(|i| (i + 1).min(max)).unwrap_or(0);
        self.table_state.select(Some(i));
    }

    fn scroll_up(&mut self) {
        let i = self.table_state.selected().map(|i| i.saturating_sub(1)).unwrap_or(0);
        self.table_state.select(Some(i));
    }
}

// ─── UI ──────────────────────────────────────────────────────────────────────

fn render(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let chunks = Layout::vertical([
        Constraint::Length(1), // title bar
        Constraint::Min(10),   // charts
        Constraint::Min(7),    // process table
        Constraint::Length(1), // status bar
    ])
    .split(area);

    render_title(f, app, chunks[0]);
    render_charts(f, app, chunks[1]);
    render_procs(f, app, chunks[2]);
    render_status(f, app, chunks[3]);
}

fn delta_str(current: u64, prev: Option<u64>) -> String {
    match prev {
        None => String::new(),
        Some(p) => {
            let (sign, d) = if current >= p {
                ('+', current - p)
            } else {
                ('-', p - current)
            };
            format!(" {sign}{d}")
        }
    }
}

fn render_title(f: &mut Frame, app: &App, area: Rect) {
    let cur = app.current();
    let prev = app.prev();
    let collecting = if app.collecting { "  collecting…" } else { "" };

    let text = format!(
        " pmon   ESTABLISHED: {}{:>6}   TIME_WAIT: {}{:>6}   CLOSE_WAIT: {}{:>6}   history: {}min{}",
        cur.established,
        delta_str(cur.established, prev.map(|p| p.established)),
        cur.time_wait,
        delta_str(cur.time_wait, prev.map(|p| p.time_wait)),
        cur.close_wait,
        delta_str(cur.close_wait, prev.map(|p| p.close_wait)),
        app.history_minutes(),
        collecting,
    );

    f.render_widget(
        Paragraph::new(text)
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        area,
    );
}

fn render_charts(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::horizontal([
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
    ])
    .split(area);

    let cur = app.current();
    let est_data = app.series(|s| s.established);
    let tw_data = app.series(|s| s.time_wait);
    let cw_data = app.series(|s| s.close_wait);

    render_line_chart(f, cols[0], "ESTABLISHED", Color::Green,  &est_data, cur.established);
    render_line_chart(f, cols[1], "TIME_WAIT",   Color::Yellow, &tw_data,  cur.time_wait);
    render_line_chart(f, cols[2], "CLOSE_WAIT",  Color::Red,    &cw_data,  cur.close_wait);
}

fn render_line_chart(
    f: &mut Frame,
    area: Rect,
    title: &str,
    color: Color,
    data: &[(f64, f64)],
    current: u64,
) {
    let max_y = data.iter().map(|&(_, y)| y as u64).max().unwrap_or(0).max(1);
    let y_max = (max_y as f64 * 1.3).ceil().max(2.0);

    let (x_min, x_max) = match (data.first(), data.last()) {
        (Some(&(first, _)), Some(&(last, _))) if last > first => (first, last),
        (Some(&(t, _)), _) => (t - 1.0, t + 1.0),
        _ => (0.0, 1.0),
    };

    let peak = data.iter().map(|&(_, y)| y as u64).max().unwrap_or(0);

    let dataset = Dataset::default()
        .graph_type(GraphType::Line)
        .marker(symbols::Marker::Braille)
        .style(Style::default().fg(color))
        .data(data);

    let fmt_min = |secs: f64| format!("{:.0}m", secs / 60.0);
    let x_labels = vec![
        Span::raw(fmt_min(x_min)),
        Span::raw(fmt_min((x_min + x_max) / 2.0)),
        Span::raw(fmt_min(x_max)),
    ];
    let y_labels = vec![
        Span::raw("0"),
        Span::raw(format!("{}", y_max as u64 / 2)),
        Span::raw(format!("{}", y_max as u64)),
    ];

    let chart = Chart::new(vec![dataset])
        .block(
            Block::bordered()
                .title(format!(" {title}  now:{current}  peak:{peak} "))
                .border_style(Style::default().fg(color)),
        )
        .x_axis(Axis::default().bounds([x_min, x_max]).labels(x_labels))
        .y_axis(Axis::default().bounds([0.0, y_max]).labels(y_labels));

    f.render_widget(chart, area);
}

fn render_procs(f: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(["PID", "Process", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "TOTAL"])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        );

    let rows: Vec<Row> = app
        .procs
        .iter()
        .map(|p| {
            // Highlight rows that look problematic
            let color = if p.close_wait >= 5 {
                Color::Red
            } else if p.time_wait >= 50 {
                Color::Yellow
            } else {
                Color::Reset
            };
            Row::new([
                p.pid.to_string(),
                p.name.clone(),
                p.established.to_string(),
                p.time_wait.to_string(),
                p.close_wait.to_string(),
                p.total().to_string(),
            ])
            .style(Style::default().fg(color))
        })
        .collect();

    let widths = [
        Constraint::Length(7),
        Constraint::Min(20),
        Constraint::Length(13),
        Constraint::Length(10),
        Constraint::Length(11),
        Constraint::Length(7),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::bordered()
                .title(" Top Processes  (red=CLOSE_WAIT≥5  yellow=TIME_WAIT≥50) ")
                .border_style(Style::default().fg(Color::Blue)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let text = format!(
        " [q/Esc] Quit   [↑↓ / j k] Scroll processes   Next refresh: {}s",
        app.secs_to_next()
    );
    f.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let start = Instant::now();
    let (tx, rx) = mpsc::channel();
    spawn_collector(tx, start);

    let mut app = App::new(rx);

    loop {
        app.poll();
        terminal.draw(|f| render(f, &mut app))?;

        // Short poll so the UI redraws smoothly (countdown, collecting indicator)
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
