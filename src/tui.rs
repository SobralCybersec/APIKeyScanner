use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::io;
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
    pub should_quit: bool,
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
            should_quit: false,
            spinner_tick: 0,
        }
    }

    pub fn add_log(&mut self, message: String) {
        self.logs.push(format!("[{}] {}", self.elapsed_time(), message));
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
        let elapsed = self.start_time.elapsed();
        format!("{:02}:{:02}", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
    }

    fn spinner_char(&self) -> &str {
        let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        frames[(self.spinner_tick as usize / 3) % frames.len()]
    }
}

pub fn render_tui(frame: &mut Frame, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(3),  // Progress bar
            Constraint::Length(7),  // Stats
            Constraint::Min(5),     // Logs
            Constraint::Length(3),  // Footer
        ])
        .split(frame.area());

    render_header(frame, chunks[0], app);
    render_progress(frame, chunks[1], app);
    render_stats(frame, chunks[2], app);
    render_logs(frame, chunks[3], app);
    render_footer(frame, chunks[4], app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let title = vec![
        Line::from(vec![
            Span::styled("API Key Scanner v2.0", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(" - Rust Edition", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(app.spinner_char(), Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled(&app.status, Style::default().fg(Color::Yellow)),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Scanner Status ");

    let paragraph = Paragraph::new(title)
        .block(block)
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, area);
}

fn render_progress(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let label = format!(
        "Query {}/{} | Repos: {} | Findings: {}",
        app.current_query,
        app.total_queries,
        app.repos_scanned,
        app.findings_count
    );

    let gauge = Gauge::default()
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Scan Progress "))
        .gauge_style(Style::default()
            .fg(if app.progress < 30.0 {
                Color::Red
            } else if app.progress < 70.0 {
                Color::Yellow
            } else {
                Color::Green
            })
            .bg(Color::Black))
        .percent(app.progress as u16)
        .label(label)
        .use_unicode(true);

    frame.render_widget(gauge, area);
}

fn render_stats(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let stats_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(area);

    // Left: API Stats
    let api_stats = vec![
        Line::from(vec![
            Span::styled("API Requests: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}/{}", app.requests_made, app.max_requests),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            ),
        ]),
        Line::from(vec![
            Span::styled("Rate Limit: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}%", (app.requests_made as f64 / app.max_requests as f64 * 100.0) as u16),
                Style::default().fg(if app.requests_made as f64 / app.max_requests as f64 > 0.8 {
                    Color::Red
                } else {
                    Color::Green
                })
            ),
        ]),
    ];

    let api_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue))
        .title(" API Usage ");

    frame.render_widget(
        Paragraph::new(api_stats).block(api_block).alignment(Alignment::Center),
        stats_layout[0]
    );

    // Middle: Findings Stats
    let findings_stats = vec![
        Line::from(vec![
            Span::styled("Total Keys: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", app.findings_count),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            ),
        ]),
        Line::from(vec![
            Span::styled("High Entropy: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", app.high_entropy_count),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            ),
        ]),
    ];

    let findings_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Findings ");

    frame.render_widget(
        Paragraph::new(findings_stats).block(findings_block).alignment(Alignment::Center),
        stats_layout[1]
    );

    // Right: Time Stats
    let time_stats = vec![
        Line::from(vec![
            Span::styled("Elapsed: ", Style::default().fg(Color::Gray)),
            Span::styled(
                app.elapsed_time(),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            ),
        ]),
        Line::from(vec![
            Span::styled("Repos/min: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:.1}", app.repos_scanned as f64 / (app.start_time.elapsed().as_secs() as f64 / 60.0).max(0.1)),
                Style::default().fg(Color::Green)
            ),
        ]),
    ];

    let time_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(" Performance ");

    frame.render_widget(
        Paragraph::new(time_stats).block(time_block).alignment(Alignment::Center),
        stats_layout[2]
    );
}

fn render_logs(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let logs: Vec<ListItem> = app.logs
        .iter()
        .rev()
        .take(area.height.saturating_sub(2) as usize)
        .rev()
        .map(|log| {
            let style = if log.contains("WARNING") || log.contains("found") {
                Style::default().fg(Color::Yellow)
            } else if log.contains("complete") {
                Style::default().fg(Color::Green)
            } else if log.contains("ERROR") || log.contains("error") {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(log.as_str()).style(style)
        })
        .collect();

    let logs_list = List::new(logs)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta))
            .title(" Activity Log "));

    frame.render_widget(logs_list, area);
}

fn render_footer(frame: &mut Frame, area: Rect, _app: &TuiApp) {
    let footer = vec![
        Line::from(vec![
            Span::styled("Press ", Style::default().fg(Color::Gray)),
            Span::styled("q", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled(" to quit | ", Style::default().fg(Color::Gray)),
            Span::styled("p", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" to pause | ", Style::default().fg(Color::Gray)),
            Span::styled("s", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled(" to save", Style::default().fg(Color::Gray)),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Controls ");

    let paragraph = Paragraph::new(footer)
        .block(block)
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, area);
}

pub fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

pub fn restore_terminal(mut terminal: Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

pub fn handle_events(app: &mut TuiApp, timeout: Duration) -> Result<bool> {
    if event::poll(timeout)? {
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        app.should_quit = true;
                        return Ok(true);
                    }
                    KeyCode::Char('p') => {
                        app.add_log("Scan paused by user".to_string());
                    }
                    KeyCode::Char('s') => {
                        app.add_log("Saving current findings...".to_string());
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(false)
}
