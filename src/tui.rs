use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind},
    execute, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{self, ClearType},
};
use std::io::{self, Write};
use std::time::{Duration, Instant};

pub struct TuiApp {
    pub status: String,
    pub progress: f64,
    pub total_queries: usize,
    pub current_query: usize,
    pub repos_scanned: usize,
    pub findings_count: usize,
    pub high_entropy_count: usize,
    pub requests_made: usize,
    pub max_requests: usize,
    pub logs: Vec<String>,
    pub start_time: Instant,
    pub save_requested: bool,
    /// Set by 'q' — signals the scan task to finish its current batch then stop.
    pub stop_requested: bool,
    pub spinner_tick: u64,
}

impl TuiApp {
    pub fn new(max_requests: usize) -> Self {
        Self {
            status: "Initializing...".to_string(),
            progress: 0.0,
            total_queries: 0,
            current_query: 0,
            repos_scanned: 0,
            findings_count: 0,
            high_entropy_count: 0,
            requests_made: 0,
            max_requests,
            logs: Vec::new(),
            start_time: Instant::now(),
            save_requested: false,
            stop_requested: false,
            spinner_tick: 0,
        }
    }

    pub fn add_log(&mut self, message: String) {
        self.logs.push(format!("[{}] {}", self.elapsed_time(), message));
        // Keep a rolling window of the last 100 log lines.
        if self.logs.len() > 100 {
            self.logs.remove(0);
        }
    }

    pub fn update_progress(&mut self) {
        if self.total_queries > 0 {
            self.progress = (self.current_query as f64 / self.total_queries as f64) * 100.0;
        }
    }

    pub fn tick(&mut self) {
        self.spinner_tick = self.spinner_tick.wrapping_add(1);
    }

    fn elapsed_time(&self) -> String {
        let e = self.start_time.elapsed();
        format!("{:02}:{:02}", e.as_secs() / 60, e.as_secs() % 60)
    }

    fn spinner_char(&self) -> char {
        const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        FRAMES[(self.spinner_tick as usize / 3) % FRAMES.len()]
    }
}

// ── Terminal setup / teardown ────────────────────────────────────────────────

/// Owns the raw-mode terminal. Drop via [`restore_terminal`]; do not drop directly.
pub struct Terminal {
    stdout: io::Stdout,
}

pub fn setup_terminal() -> Result<Terminal> {
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide)?;
    Ok(Terminal { stdout })
}

pub fn restore_terminal(mut t: Terminal) -> Result<()> {
    execute!(t.stdout, terminal::LeaveAlternateScreen, cursor::Show)?;
    terminal::disable_raw_mode()?;
    Ok(())
}

// ── Rendering ────────────────────────────────────────────────────────────────

pub fn render_tui(t: &mut Terminal, app: &TuiApp) {
    // Render errors are non-fatal (e.g. terminal resize races); silently ignore.
    let _ = render_inner(&mut t.stdout, app);
}

fn render_inner(out: &mut io::Stdout, app: &TuiApp) -> Result<()> {
    let (cols, rows) = terminal::size().unwrap_or((80, 24));

    queue!(out, cursor::MoveTo(0, 0), terminal::Clear(ClearType::All))?;

    // ── Row 0: header ────────────────────────────────────────────────────────
    let header = format!(
        " {} {} | API Key Scanner v2.0",
        app.spinner_char(),
        app.status
    );
    queue!(
        out,
        SetForegroundColor(Color::Cyan),
        Print(truncate(&header, cols as usize)),
        ResetColor,
        Print("\r\n"),
    )?;

    // ── Row 1: progress bar ──────────────────────────────────────────────────
    let bar_width = (cols as usize).saturating_sub(20).max(10);
    let filled = ((app.progress / 100.0) * bar_width as f64) as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);
    let bar_color = if app.progress < 30.0 {
        Color::Red
    } else if app.progress < 70.0 {
        Color::Yellow
    } else {
        Color::Green
    };
    queue!(
        out,
        SetForegroundColor(bar_color),
        Print(format!(" [{bar}] {:.0}%\r\n", app.progress)),
        ResetColor,
    )?;

    // ── Row 2: stats ─────────────────────────────────────────────────────────
    let rate_color = if app.requests_made as f64 / app.max_requests.max(1) as f64 > 0.8 {
        Color::Red
    } else {
        Color::Green
    };
    let elapsed = app.elapsed_time();
    let repos_per_min = app.repos_scanned as f64
        / (app.start_time.elapsed().as_secs_f64() / 60.0).max(0.01);

    queue!(
        out,
        SetForegroundColor(Color::Grey),
        Print(format!(
            " Queries: {}/{} | Repos: {} | ",
            app.current_query, app.total_queries, app.repos_scanned
        )),
        ResetColor,
        SetForegroundColor(Color::Yellow),
        Print(format!("Keys: {} ", app.findings_count)),
        SetForegroundColor(Color::Red),
        Print(format!("(hi-entropy: {}) ", app.high_entropy_count)),
        ResetColor,
        SetForegroundColor(rate_color),
        Print(format!(
            "| API: {}/{} | {}  {:.1} r/m\r\n",
            app.requests_made, app.max_requests, elapsed, repos_per_min
        )),
        ResetColor,
    )?;

    // ── Row 3: separator ─────────────────────────────────────────────────────
    queue!(
        out,
        SetForegroundColor(Color::DarkGrey),
        Print(format!(" {}\r\n", "─".repeat((cols as usize).saturating_sub(2)))),
        ResetColor,
    )?;

    // ── Rows 4..(rows-2): log lines ──────────────────────────────────────────
    let log_rows = (rows as usize).saturating_sub(6);
    let skip = app.logs.len().saturating_sub(log_rows);
    for log in app.logs.iter().skip(skip) {
        let color = if log.contains("WARNING") || log.contains("found") {
            Color::Yellow
        } else if log.contains("complete") {
            Color::Green
        } else if log.contains("ERROR") || log.contains("error") {
            Color::Red
        } else {
            Color::White
        };
        queue!(
            out,
            SetForegroundColor(color),
            Print(format!(" {}\r\n", truncate(log, cols as usize - 2))),
            ResetColor,
        )?;
    }

    // ── Last row: footer ─────────────────────────────────────────────────────
    queue!(
        out,
        cursor::MoveTo(0, rows - 1),
        SetForegroundColor(Color::DarkGrey),
        Print(" [q] stop+save  [s] save now"),
        ResetColor,
    )?;

    out.flush()?;
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        chars[..max.saturating_sub(1)].iter().collect::<String>() + "…"
    }
}

// ── Event handling ───────────────────────────────────────────────────────────

/// Poll for a single keypress within `timeout`.
///
/// Returns `true` if the user requested quit (`q` / `Esc`).
pub fn handle_events(app: &mut TuiApp, timeout: Duration) -> Result<bool> {
    if event::poll(timeout)? {
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.stop_requested = true;
                            app.add_log("Stopping — finishing current batch, then saving & validating...".to_string());
                            app.status = "Stopping after current batch...".to_string();
                        }
                        KeyCode::Char('p') => {
                            app.add_log("Scan paused by user".to_string());
                        }
                        KeyCode::Char('s') => {
                            app.save_requested = true;
                            app.add_log("Save requested — flushing findings...".to_string());
                        }
                        _ => {}
                    }
            }
        }
    }
    Ok(false)
}