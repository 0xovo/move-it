//! The app's own log, and the report a person can send when something goes wrong.
//!
//! The shell shows the newest lines on the Logs screen; [`LogBuffer::export`]
//! renders the whole buffer as one text file the person can save or share.
//!
//! Two disciplines hold here:
//!
//! - Bounded. The buffer keeps at most [`MAX_LINES`] lines, truncates each
//!   message to [`MAX_MESSAGE_CHARS`], and counts the lines it drops, so the
//!   log can never grow without limit, in memory or in the export. Cleaning
//!   also works on a bounded prefix of the input, so one huge message costs
//!   bounded memory too.
//! - Nothing secret is ever stored. Callers log events and counts ("move
//!   finished, 1240 logins and cookies"), never values: no sync key, no
//!   browser password, no cookie or login contents, no profile data. As a
//!   backstop, every message is normalised and redacted on the way in (see
//!   [`redact`]), so a caller that slips up still cannot put a key, a
//!   labelled secret or a pairing code into the buffer, the screen or the
//!   export. Redaction happens at push time: the buffer never holds the
//!   value, even briefly.
//!
//! The backstop has a floor, and it is worth being plain about it: a short
//! value with no label and no key shape (a twelve-character password in
//! plain prose, a key broken into pieces under eight characters) is not
//! caught. That is why "never log values" is the rule and this is only the
//! net under it.
//!
//! The caller owns the clock: nothing here reads the system time, which keeps
//! the buffer deterministic to test. The app surface stamps lines with its
//! `now_secs` as it pushes them, and owns the buffer the way it owns the
//! config: one owner, no locking inside.

use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Most lines the buffer keeps. Older lines are dropped (and counted).
pub const MAX_LINES: usize = 500;
/// Longest message kept, in characters. Longer messages are truncated.
pub const MAX_MESSAGE_CHARS: usize = 240;
/// Unbroken token runs at least this long are treated as secrets. Keys and
/// cookie values are base64 or hex and run longer than this; words do not.
const TOKEN_RUN_MIN: usize = 22;
/// Words that turn a bare number in front of them into a count in prose
/// ("123456 bytes"), never a code.
const COUNT_UNITS: &[&str] = &[
    "bytes", "logins", "cookies", "items", "files", "records", "seconds",
    "minutes", "hours", "profiles", "boxes", "bookmarks", "pages", "entries",
    "rows", "urls", "sites", "history",
];

/// How much raw input cleaning will look at, as a multiple of the kept
/// length. Anything past the kept length is dropped anyway; this cap keeps
/// the cleaning of one huge message at bounded cost.
const CLEAN_PREFIX_CHARS: usize = MAX_MESSAGE_CHARS * 4;
/// Labels whose value is redacted however short it is, once a separator
/// (`=`, `:`, `=>`) or a quoted/bracketed shape gives the value away
/// ("password = ...", `{"password":"..."}`).
const SECRET_LABELS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "authorization",
    "sync key",
    "sync_key",
    "pairing code",
    "pairing_code",
    "api_key",
    "api-key",
    "apikey",
    "key",
    "sid",
    "session id",
    "session_id",
];
/// Labels that name their value with bare whitespace ("Bearer ..."). Kept
/// tiny on purpose: these words barely exist in ordinary prose, unlike the
/// ones above ("the password is wrong" must survive).
const BARE_SECRET_LABELS: &[&str] = &["bearer"];

/// How serious a line is. The Logs screen colours by this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    /// The label used on screen and in the export: INFO, WARN or ERROR.
    pub fn label(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One log line: when it happened (unix seconds), how serious, and the text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogLine {
    pub at_unix: u64,
    pub level: Level,
    pub message: String,
}

/// A bounded ring of log lines, plus the last operation's outcome summary.
///
/// The app surface pushes a line for each thing worth remembering and records
/// the outcome of each operation (usually a move) with
/// [`LogBuffer::record_outcome`].
#[derive(Debug, Clone, Default)]
pub struct LogBuffer {
    lines: VecDeque<LogLine>,
    dropped: u64,
    last_outcome: Option<String>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a line. The message is cleaned before it is stored: normalised,
    /// forced to one line, redacted, truncated. When the buffer is full the
    /// oldest line is dropped and counted.
    pub fn push(&mut self, at_unix: u64, level: Level, message: &str) {
        let line = LogLine { at_unix, level, message: clean(message) };
        if self.lines.len() == MAX_LINES {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(line);
    }

    /// Add an INFO line.
    pub fn info(&mut self, at_unix: u64, message: &str) {
        self.push(at_unix, Level::Info, message);
    }

    /// Add a WARN line.
    pub fn warn(&mut self, at_unix: u64, message: &str) {
        self.push(at_unix, Level::Warn, message);
    }

    /// Add an ERROR line.
    pub fn error(&mut self, at_unix: u64, message: &str) {
        self.push(at_unix, Level::Error, message);
    }

    /// Record how the last operation ended, for the export header. Cleaned
    /// and redacted like any message.
    pub fn record_outcome(&mut self, summary: &str) {
        self.last_outcome = Some(clean(summary));
    }

    /// The last recorded operation outcome, if any.
    pub fn last_outcome(&self) -> Option<&str> {
        self.last_outcome.as_deref()
    }

    /// How many lines are currently held.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// True when no lines are held.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// How many older lines were dropped because the buffer was full.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// All held lines, oldest to newest.
    pub fn lines(&self) -> impl Iterator<Item = &LogLine> {
        self.lines.iter()
    }

    /// The newest `n` lines, oldest to newest: what the app surface's
    /// `logs_recent` hands to the Logs screen.
    pub fn recent(&self, n: usize) -> Vec<LogLine> {
        let skip = self.lines.len().saturating_sub(n);
        self.lines.iter().skip(skip).cloned().collect()
    }

    /// The whole log as one text report: version, OS, export time, the last
    /// operation's outcome, then every held line oldest to newest. This is
    /// what the app surface's `export_logs` returns and the shell saves or
    /// shares as a file.
    pub fn export(&self, exported_at_unix: u64) -> String {
        let mut out = String::new();
        out.push_str("Move It log export\n");
        out.push_str(&format!("version: {}\n", env!("CARGO_PKG_VERSION")));
        out.push_str(&format!("os: {}\n", std::env::consts::OS));
        out.push_str(&format!("exported: {}\n", format_time(exported_at_unix)));
        match &self.last_outcome {
            Some(summary) => out.push_str(&format!("last operation: {summary}\n")),
            None => out.push_str("last operation: none recorded\n"),
        }
        out.push_str(&format!("lines: {}", self.lines.len()));
        if self.dropped > 0 {
            out.push_str(&format!(" ({} earlier dropped)", self.dropped));
        }
        out.push('\n');
        out.push_str("---\n");
        for line in &self.lines {
            out.push_str(&format!(
                "[{}] {} {}\n",
                format_time(line.at_unix),
                line.level.label(),
                line.message
            ));
        }
        out
    }
}

/// Make a message safe to store: bounded, normalised, one line, redacted,
/// at most [`MAX_MESSAGE_CHARS`] characters.
fn clean(message: &str) -> String {
    let bounded: String = message.chars().take(CLEAN_PREFIX_CHARS).collect();
    let normalised: String = bounded.chars().filter_map(normalise_char).collect();
    redact(&normalised).chars().take(MAX_MESSAGE_CHARS).collect()
}

/// One character of input hygiene:
///
/// - format characters (zero-width spaces, bidi marks, the byte-order mark)
///   are dropped: they split a token run on screen while joining it in
///   fact, which is exactly how a key would hide from the token pass;
/// - non-breaking and ideographic spaces become plain spaces;
/// - fullwidth forms fold to ASCII, so a fullwidth label or digit is seen
///   for what it is;
/// - control characters become spaces, so a message can never smuggle in
///   extra lines that look like log entries.
fn normalise_char(c: char) -> Option<char> {
    match c {
        '\u{00ad}' | '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}' | '\u{feff}' => None,
        '\u{00a0}' | '\u{3000}' => Some(' '),
        '\u{ff01}'..='\u{ff5e}' => char::from_u32(c as u32 - 0xfee0),
        c if c.is_control() => Some(' '),
        c => Some(c),
    }
}

/// Scrub secret-shaped material out of a message. Two passes:
///
/// - Token pass ([`redact_tokens`]): runs and clusters of the base64/hex
///   alphabet that are long enough to be key material, pure-hex fragments,
///   and every shape of a pairing code.
/// - Label pass ([`redact_labelled`]): a value after a secret label, in
///   structured shapes, however short the value is.
fn redact(message: &str) -> String {
    redact_labelled(&redact_tokens(&scrub_home_paths(&scrub_url_userinfo(message))))
}

/// Credentials in a URL authority are private even when both are short.
fn scrub_url_userinfo(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(i) = rest.find("://") {
        let start = i + 3;
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let end = rest.find(|c: char| matches!(c, '/' | '?' | '#') || c.is_whitespace()).unwrap_or(rest.len());
        let authority = &rest[..end];
        if let Some(at) = authority.rfind('@') {
            out.push_str("<redacted>@");
            out.push_str(&authority[at + 1..]);
        } else {
            out.push_str(authority);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// The segment of a home path that names the person: in `/home/<name>/...`,
/// `/Users/<name>/...` and `C:\Users\<name>\...` the name itself is
/// private, and it is short enough to slip past every other pass. It is
/// replaced with `<user>` wherever it sits.
fn scrub_home_paths(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    loop {
        let lower = rest.to_ascii_lowercase();
        let hit = ["/home/", "/users/", "\\users\\"]
            .iter()
            .filter_map(|m| lower.find(m).map(|i| (i, m.len())))
            .min_by_key(|(i, _)| *i);
        let Some((i, len)) = hit else {
            out.push_str(rest);
            break;
        };
        let after = &rest[i + len..];
        let separators = after.len() - after.trim_start_matches(['/', '\\']).len();
        let name = &after[separators..];
        let seg_len = name.find(|c: char| c == '/' || c == '\\' || c.is_whitespace()
            || matches!(c, '"' | '\'' | ',' | ';')).unwrap_or(name.len());
        out.push_str(&rest[..i + len + separators]);
        if seg_len > 0 { out.push_str("<user>"); }
        rest = &name[seg_len..];
    }
    out
}

/// True for the characters a base64 or hex value is made of.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// One span of a message: a run of token characters, or the text between
/// runs. Slices always fall on character boundaries.
struct Span<'a> {
    text: &'a str,
    is_run: bool,
}

fn path_end(message: &str, start: usize) -> Option<usize> {
    let rest = &message[start..];
    let boundary = start == 0 || message[..start].ends_with(|c: char| c.is_whitespace() || matches!(c, '=' | '(' | '[' | '"' | '\''));
    if !boundary { return None; }
    let drive = rest.as_bytes().get(..3).is_some_and(|b|
        b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'/' | b'\\'));
    if !drive && !rest.starts_with('/') && !rest.starts_with("~/") {
        return None;
    }
    let len = rest.find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')' | ']' | '}'))
        .unwrap_or(rest.len());
    Some(start + len)
}

fn spans(message: &str) -> Vec<Span<'_>> {
    let bytes = message.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if let Some(end) = path_end(message, i) {
            out.push(Span { text: &message[i..end], is_run: false });
            i = end;
            continue;
        }
        if is_token_byte(bytes[i]) {
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            out.push(Span { text: &message[start..i], is_run: true });
        } else {
            while i < bytes.len() && !is_token_byte(bytes[i]) {
                i += utf8_len(bytes[i]);
            }
            out.push(Span { text: &message[start..i], is_run: false });
        }
    }
    out
}

/// A run that looks like a chunk of encoded material rather than a word:
/// at least eight characters, and carrying a digit or mixed case. Plain
/// words fail at least one of those.
fn dense(run: &str) -> bool {
    run.len() >= 8
        && (run.bytes().any(|b| b.is_ascii_digit())
            || (run.bytes().any(|b| b.is_ascii_lowercase())
                && run.bytes().any(|b| b.is_ascii_uppercase())))
}

/// A run of pure hex (a hash or key fragment): long, and mixing digits with
/// a-f letters. A word is never shaped like this once it has a digit in it.
fn hex_shaped(run: &str) -> bool {
    run.len() >= 16
        && run.bytes().all(|b| b.is_ascii_hexdigit())
        && run.bytes().any(|b| b.is_ascii_digit())
        && run.bytes().any(|b| b.is_ascii_alphabetic())
}

/// True when `run` is exactly six digits once dashes are removed: the shape
/// of a pairing code ("482913", "482-913").
fn code_shaped(run: &str) -> bool {
    let mut digits = 0;
    for b in run.bytes() {
        if b.is_ascii_digit() {
            digits += 1;
        } else if b != b'-' {
            return false;
        }
    }
    digits == 6
}

/// Redact one token run on its own merits, or keep it (still scanning inside
/// it for a bare six-digit span, per [`redact_inner_six`]).
fn redact_run(run: &str) -> String {
    if run.len() >= TOKEN_RUN_MIN || code_shaped(run) || hex_shaped(run) {
        "<redacted>".to_string()
    } else {
        redact_inner_six(run)
    }
}

/// Within a kept run, a bare six-digit span is code-shaped wherever it sits
/// ("code/482913"): redact just the digits.
fn redact_inner_six(run: &str) -> String {
    let bytes = run.as_bytes();
    let mut out = String::with_capacity(run.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i - start == 6 {
                out.push_str("<redacted>");
            } else {
                out.push_str(&run[start..i]);
            }
        } else {
            out.push(bytes[i] as char); // token bytes are ASCII
            i += 1;
        }
    }
    out
}

fn redact_tokens(message: &str) -> String {
    let all = spans(message);
    let mut out = String::with_capacity(message.len());
    let mut i = 0;
    while i < all.len() {
        let span = &all[i];
        if !span.is_run {
            out.push_str(span.text);
            i += 1;
            continue;
        }
        // A cluster: this run and the dense runs after it, joined by single
        // spaces or dots. A key pasted in chunks, or a dotted token, is one
        // secret in several runs; judged together they are long enough.
        let mut last = i;
        let mut total = 0;
        let mut members = 0;
        let mut j = i;
        while j < all.len() && all[j].is_run && dense(all[j].text) {
            total += all[j].text.len();
            members += 1;
            last = j;
            if j + 2 < all.len()
                && !all[j + 1].is_run
                && (all[j + 1].text == " " || all[j + 1].text == ".")
                && all[j + 2].is_run
                && dense(all[j + 2].text)
            {
                j += 2;
            } else {
                break;
            }
        }
        if members >= 2 && total >= TOKEN_RUN_MIN {
            out.push_str("<redacted>");
            i = last + 1;
            continue;
        }
        // A pairing code spelled digit by digit ("4 8 2 9 1 3"): six
        // one-digit runs joined by single spaces.
        if span.text.len() == 1 && span.text.bytes().all(|b| b.is_ascii_digit()) {
            let mut ok = true;
            for step in 1..6 {
                let sep = i + step * 2 - 1;
                let run = i + step * 2;
                if run >= all.len()
                    || all[sep].is_run
                    || all[sep].text != " "
                    || !all[run].is_run
                    || all[run].text.len() != 1
                    || !all[run].text.bytes().all(|b| b.is_ascii_digit())
                {
                    ok = false;
                    break;
                }
            }
            if ok {
                out.push_str("<redacted>");
                i += 11;
                continue;
            }
        }
        // A bare six-digit run right before a count unit ("wrote 123456
        // bytes") is a count in prose, not a pairing code.
        if span.text.len() == 6
            && span.text.bytes().all(|b| b.is_ascii_digit())
            && i + 2 < all.len()
            && !all[i + 1].is_run
            && all[i + 1].text == " "
            && all[i + 2].is_run
            && COUNT_UNITS.contains(&all[i + 2].text.to_ascii_lowercase().as_str())
        {
            out.push_str(span.text);
            i += 1;
            continue;
        }
        // A pairing code in display groups ("482 913", any spacing): a
        // three-digit run, spaces, another three-digit run, then no digit.
        if span.text.len() == 3
            && span.text.bytes().all(|b| b.is_ascii_digit())
            && i + 2 < all.len()
            && !all[i + 1].is_run
            && !all[i + 1].text.is_empty()
            && all[i + 1].text.bytes().all(|b| b == b' ')
            && all[i + 2].is_run
            && all[i + 2].text.len() == 3
            && all[i + 2].text.bytes().all(|b| b.is_ascii_digit())
            && (i + 3 >= all.len()
                || all[i + 3].is_run
                || !all[i + 3].text.starts_with(|c: char| c.is_ascii_digit()))
        {
            out.push_str("<redacted>");
            i += 3;
            continue;
        }
        out.push_str(&redact_run(span.text));
        i += 1;
    }
    out
}

/// True for a letter or digit: a label only counts at a word edge, so the
/// "key" inside "monkey" is not a label.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Does `label` sit at byte `i` in `message`, ending at a word edge?
fn label_at(message: &str, i: usize, label: &str) -> bool {
    let bytes = message.as_bytes();
    let end = i + label.len();
    end <= bytes.len()
        && message.is_char_boundary(end)
        && message[i..end].eq_ignore_ascii_case(label)
        && (end >= bytes.len() || !is_word_byte(bytes[end]))
}

fn redact_labelled(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut out = String::with_capacity(message.len());
    let mut i = 0;
    while i < bytes.len() {
        let at_boundary = i == 0 || !is_word_byte(bytes[i - 1]);
        let mut fired = false;
        if at_boundary {
            for label in BARE_SECRET_LABELS {
                if label_at(message, i, label) {
                    // "Bearer <value>": whitespace alone gives it away. The
                    // value runs to the end of the line.
                    let mut j = i + label.len();
                    while j < bytes.len() && bytes[j] == b' ' {
                        j += 1;
                    }
                    if j > i + label.len() && j < bytes.len() {
                        out.push_str(&message[i..j]);
                        out.push_str("<redacted>");
                        i = message[j..].find([',', ';']).map_or(bytes.len(), |end| j + end);
                        fired = true;
                    }
                    break;
                }
            }
            if !fired {
                for label in SECRET_LABELS {
                    // A plural label names the same secret ("cookies:").
                    let plural;
                    let candidates: [&str; 2] = if label.ends_with('s') {
                        [*label, *label]
                    } else {
                        plural = format!("{label}s");
                        [*label, &plural]
                    };
                    let mut hit = None;
                    for cand in candidates {
                        if label_at(message, i, cand) {
                            hit = Some(cand.len());
                            break;
                        }
                    }
                    let Some(label_len) = hit else { continue };
                    let label = &message[i..i + label_len];
                    // Between the label and its value there may be spaces,
                    // quotes and brackets ({"password": ...}, [password]=...)
                    let mut j = i + label.len();
                    let mut skipped_opener = false;
                    loop {
                        while j < bytes.len() && bytes[j] == b' ' {
                            j += 1;
                        }
                        if j < bytes.len()
                            && matches!(
                                bytes[j],
                                b'"' | b'\'' | b'[' | b']' | b'(' | b')' | b'{' | b'}'
                            )
                        {
                            skipped_opener = true;
                            j += 1;
                        } else {
                            break;
                        }
                    }
                    let mut has_separator = false;
                    if j < bytes.len() && (bytes[j] == b'=' || bytes[j] == b':') {
                        has_separator = true;
                        j += 1;
                        if bytes[j - 1] == b'=' && j < bytes.len() && bytes[j] == b'>' {
                            j += 1; // "=>"
                        }
                        while j < bytes.len()
                            && (bytes[j] == b' ' || bytes[j] == b'"' || bytes[j] == b'\'')
                        {
                            j += 1;
                        }
                    }
                    if has_separator {
                        // A comma or semicolon starts the next field.
                        out.push_str(&message[i..j]);
                        out.push_str("<redacted>");
                        i = message[j..].find([',', ';']).map_or(bytes.len(), |end| j + end);
                        fired = true;
                    } else if skipped_opener && j < bytes.len() {
                        // password(hunter2): a bracketed value straight
                        // after the label. It counts only when the closer
                        // follows the value, so "(see notes)" in prose is
                        // not mistaken for a value.
                        let start = j;
                        while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        let value = &message[start..j];
                        let closed = j < bytes.len()
                            && matches!(bytes[j], b')' | b']' | b'}' | b'"' | b'\'')
                            || (j > start
                                && matches!(value.as_bytes()[value.len() - 1], b')' | b']' | b'}'));
                        if closed && !value.is_empty() {
                            out.push_str(&message[i..start]);
                            out.push_str("<redacted>");
                            i = start + value.len();
                            fired = true;
                        }
                    }
                    if fired {
                        break;
                    }
                }
            }
        }
        if !fired {
            let len = utf8_len(bytes[i]);
            out.push_str(&message[i..i + len]);
            i += len;
        }
    }
    out
}

/// Length in bytes of the UTF-8 character starting with `first`.
fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

/// Format unix seconds as "2026-01-01 00:00:00 UTC". Pure arithmetic, no
/// clock or locale: the same input formats the same on every platform.
fn format_time(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Days since 1970-01-01 to a (year, month, day) civil date
/// (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_767_225_600; // 2026-01-01 00:00:00 UTC

    #[test]
    fn paths_keep_their_shape_and_scrub_home_names() {
        for (input, expected) in [
            ("at /home/alex/.config/BraveSoftware/Brave-Browser/Default", "at /home/<user>/.config/BraveSoftware/Brave-Browser/Default"),
            ("at /Users//alex/Library/Application Support/Chrome", "at /Users//<user>/Library/Application Support/Chrome"),
            (r"at c:\users\\alex\AppData\Local\Chrome", r"at c:\users\\<user>\AppData\Local\Chrome"),
            ("at /tmp/very-long-scratch-directory/profile/Default", "at /tmp/very-long-scratch-directory/profile/Default"),
        ] {
            assert_eq!(redact(input), expected);
        }
    }

    #[test]
    fn url_userinfo_is_redacted_and_following_fields_survive() {
        let scrubbed = redact("fetch https://user:pass@example.test/path, password=hunter2; moved 123456 history pages");
        assert!(!scrubbed.contains("user:pass"));
        assert!(!scrubbed.contains("hunter2"));
        assert!(scrubbed.contains("example.test/path"));
        assert!(scrubbed.ends_with("; moved 123456 history pages"));
        assert_eq!(redact("token=small, cookies moved"), "token=<redacted>, cookies moved");
    }

    #[test]
    fn buffer_drops_oldest_past_the_cap_and_counts_them() {
        let mut buf = LogBuffer::new();
        for i in 0..MAX_LINES {
            buf.info(T0 + i as u64, &format!("line {i}"));
        }
        assert_eq!(buf.len(), MAX_LINES);
        assert_eq!(buf.dropped(), 0);
        for i in MAX_LINES..MAX_LINES + 10 {
            buf.info(T0 + i as u64, &format!("line {i}"));
        }
        assert_eq!(buf.len(), MAX_LINES);
        assert_eq!(buf.dropped(), 10);
        assert_eq!(buf.lines().next().unwrap().message, "line 10");
        assert_eq!(buf.lines().last().unwrap().message, format!("line {}", MAX_LINES + 9));
    }

    #[test]
    fn recent_is_the_newest_lines_oldest_first() {
        let mut buf = LogBuffer::new();
        for i in 0..5 {
            buf.push(T0 + i, Level::Info, &format!("line {i}"));
        }
        let recent: Vec<String> =
            buf.recent(3).into_iter().map(|l| l.message).collect();
        assert_eq!(recent, ["line 2", "line 3", "line 4"]);
        assert_eq!(buf.recent(0).len(), 0);
        assert_eq!(buf.recent(99).len(), 5);
        assert!(LogBuffer::new().recent(5).is_empty());
    }

    #[test]
    fn export_has_the_header_then_lines_in_order() {
        let mut buf = LogBuffer::new();
        buf.record_outcome("move finished: 214 bookmarks moved");
        buf.info(T0, "paired with Office PC");
        buf.warn(T0 + 61, "2 logins could not move");
        let out = buf.export(T0 + 3600);
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some("Move It log export"));
        assert_eq!(
            lines.next(),
            Some(format!("version: {}", env!("CARGO_PKG_VERSION")).as_str())
        );
        assert!(lines.next().unwrap().starts_with("os: "));
        assert_eq!(lines.next(), Some("exported: 2026-01-01 01:00:00 UTC"));
        assert_eq!(
            lines.next(),
            Some("last operation: move finished: 214 bookmarks moved")
        );
        assert_eq!(lines.next(), Some("lines: 2"));
        assert_eq!(lines.next(), Some("---"));
        assert_eq!(
            lines.next(),
            Some("[2026-01-01 00:00:00 UTC] INFO paired with Office PC")
        );
        assert_eq!(
            lines.next(),
            Some("[2026-01-01 00:01:01 UTC] WARN 2 logins could not move")
        );
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn export_of_an_empty_buffer_says_so() {
        let out = LogBuffer::new().export(T0);
        assert!(out.contains("last operation: none recorded\n"));
        assert!(out.contains("lines: 0\n"));
        assert!(out.ends_with("---\n"));
    }

    #[test]
    fn export_reports_dropped_lines() {
        let mut buf = LogBuffer::new();
        for i in 0..MAX_LINES + 3 {
            buf.info(T0, &format!("line {i}"));
        }
        let out = buf.export(T0);
        assert!(out.contains(&format!("lines: {} (3 earlier dropped)", MAX_LINES)));
    }

    #[test]
    fn planted_secrets_cannot_reach_the_buffer_or_the_export() {
        // Fake values, shaped like the real ones the app handles.
        const FAKE_KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
        let mut buf = LogBuffer::new();
        buf.info(T0, &format!("sealed with sync key {FAKE_KEY}"));
        buf.info(T0, "the browser password=hunter2 was used");
        buf.info(T0, "sync key: abc123 was loaded");
        buf.info(T0, "user typed code 482913 on the other device");
        buf.info(T0, "user typed code: 482 913 on the other device");
        buf.info(T0, "user typed code 482-913 on the other device");
        buf.record_outcome(&format!("failed with token {FAKE_KEY}"));
        let out = buf.export(T0);
        for secret in [FAKE_KEY, "hunter2", "abc123", "482913", "482 913", "482-913"] {
            assert!(!out.contains(secret), "export leaked {secret}");
            for line in buf.lines() {
                assert!(!line.message.contains(secret), "buffer held {secret}");
            }
        }
        assert!(out.contains("<redacted>"));
        // The events themselves survive; only the values are gone.
        assert!(out.contains("sealed with sync key <redacted>"));
        assert!(out.contains("user typed code <redacted> on the other device"));
        assert!(buf.last_outcome().unwrap().contains("<redacted>"));
    }

    #[test]
    fn labelled_secrets_in_structured_shapes_are_redacted() {
        // Shapes an echoed error or a careless format string actually takes.
        for (input, secret) in [
            ("{\"password\":\"hunter2\"}", "hunter2"),
            ("{\"password\": \"hunter2\"}", "hunter2"),
            ("password => hunter2", "hunter2"),
            ("[password]=hunter2", "hunter2"),
            ("password(hunter2)", "hunter2"),
            ("password: my secret value", "secret"),
            ("Authorization: Bearer shorttok", "shorttok"),
            ("Bearer abc.def.ghi", "abc.def.ghi"),
        ] {
            let stored = clean(input);
            assert!(!stored.contains(secret), "{input} leaked {secret}: {stored}");
            assert!(stored.contains("<redacted>"), "{input} not redacted: {stored}");
        }
    }

    #[test]
    fn split_and_joined_secrets_are_redacted() {
        // A key pasted in chunks is still one key.
        let stored = clean("key MDEyMzQ1Njc4OWFiY2Rl ZjAxMjM0NTY3ODlhYmNk ZWY");
        assert!(!stored.contains("MDEyMzQ1Njc4OWFiY2Rl"), "{stored}");
        assert!(!stored.contains("ZjAxMjM0NTY3ODlhYmNk"), "{stored}");
        // A dotted token: the header segment is under the run threshold on
        // its own and must still go.
        let stored = clean("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop");
        assert!(!stored.contains("eyJhbGciOiJIUzI1NiJ9"), "{stored}");
        assert!(!stored.contains("eyJzdWIiOiIxMjM0NTY3ODkwIn0"), "{stored}");
        // A zero-width space does not split a key for us.
        let stored = clean("key MDEyMzQ1Njc4OWFiY2Rl\u{200b}ZjAxMjM0NTY3ODlhYmNkZWY");
        assert!(!stored.contains("MDEyMzQ1"), "{stored}");
        assert!(!stored.contains("ZjAxMjM0"), "{stored}");
    }

    #[test]
    fn home_paths_sids_plurals_and_spaced_codes_are_scrubbed() {
        for (input, gone) in [
            ("profile at /home/alex/.config/BraveSoftware broke", "alex"),
            ("profile at /Users/alex/Library broke", "alex"),
            ("sid=abc123 was refused", "abc123"),
            ("cookies: choc-chip-value", "choc-chip-value"),
            ("passwords: hunter2 was here", "hunter2"),
            ("the code is 4 8 2 9 1 3 ok", "4 8 2 9 1 3"),
        ] {
            let stored = clean(input);
            assert!(!stored.contains(gone), "{input} leaked {gone}: {stored}");
        }
    }

    #[test]
    fn counts_and_error_codes_are_not_secrets() {
        for msg in [
            "error code: 5 while reading the store",
            "wrote 123456 bytes to the place",
            "moved 482913 logins and cookies",
        ] {
            assert_eq!(redact(msg), msg, "over-redacted: {msg}");
        }
    }

    #[test]
    fn code_shapes_are_redacted() {
        for input in ["code 482  913", "code/482913", "code \u{ff14}\u{ff18}\u{ff12}\u{ff19}\u{ff11}\u{ff13}"] {
            let stored = clean(input);
            assert!(!stored.contains("482"), "{input} leaked: {stored}");
            assert!(!stored.contains("913"), "{input} leaked: {stored}");
            assert!(stored.contains("<redacted>"), "{input} not redacted: {stored}");
        }
    }

    #[test]
    fn normalised_labels_and_hex_fragments_are_redacted() {
        // A non-breaking space is still a space to the label pass.
        let stored = clean("password\u{00a0}=\u{00a0}hunter2");
        assert!(!stored.contains("hunter2"), "{stored}");
        // A fullwidth label folds to ASCII and is seen.
        let stored = clean("\u{ff50}\u{ff41}\u{ff53}\u{ff53}\u{ff57}\u{ff4f}\u{ff52}\u{ff44}=hunter2");
        assert!(!stored.contains("hunter2"), "{stored}");
        // A pure-hex fragment under the token threshold is still key-shaped.
        let stored = clean("saw deadbeefdeadbeefdea01 in the store");
        assert!(!stored.contains("deadbeef"), "{stored}");
    }

    #[test]
    fn prose_that_only_mentions_labels_survives() {
        // The label words are ordinary words too; without a separator or a
        // bracketed value they are prose, not secrets.
        for msg in [
            "the password is wrong, try again",
            "open the password manager and add it there",
            "the code was rejected, try again later",
            "password (see the notes) is never logged",
        ] {
            assert_eq!(redact(msg), msg, "over-redacted: {msg}");
        }
    }

    #[test]
    fn ordinary_event_lines_pass_redaction_untouched() {
        for msg in [
            "move finished: 214 bookmarks, 9,812 history items",
            "moved 1,240 logins and cookies in 12 seconds",
            "brave is still open; close it and try again",
            "paired with Office PC",
            "2 logins could not move (App-Bound, v20)",
        ] {
            assert_eq!(redact(msg), msg, "over-redacted: {msg}");
        }
    }

    #[test]
    fn messages_are_forced_to_one_line_and_truncated() {
        let mut buf = LogBuffer::new();
        buf.error(T0, "move stopped\n[2026-01-01 00:00:00 UTC] ERROR a fake line");
        let held = &buf.lines().next().unwrap().message;
        assert!(!held.contains('\n'));
        assert!(held.contains("a fake line"));
        let out = buf.export(T0);
        // The fake line never becomes a line of its own in the export: it
        // stays inside the one real line that carried it.
        let carriers: Vec<&str> = out.lines().filter(|l| l.contains("a fake line")).collect();
        assert_eq!(carriers.len(), 1);
        assert!(carriers[0].starts_with("[2026-01-01 00:00:00 UTC] ERROR move stopped"));
        let long = "word ".repeat(200);
        buf.info(T0, &long);
        assert_eq!(buf.lines().last().unwrap().message.chars().count(), MAX_MESSAGE_CHARS);
    }

    #[test]
    fn giant_inputs_are_capped_before_they_cost_anything() {
        let mut buf = LogBuffer::new();
        buf.info(T0, &"word ".repeat(200_000));
        assert_eq!(buf.lines().next().unwrap().message.chars().count(), MAX_MESSAGE_CHARS);
        // Material past the cleaning window is dropped, never stored: a key
        // hiding behind a wall of zero-width spaces does not reach the log.
        let hidden = format!("{}\u{200b}MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", "\u{200b}".repeat(2_000));
        buf.info(T0, &hidden);
        assert!(buf.lines().last().unwrap().message.is_empty());
        assert!(!buf.export(T0).contains("MDEyMzQ1"));
    }

    #[test]
    fn export_size_is_hard_bounded() {
        let mut buf = LogBuffer::new();
        let full = "word ".repeat(MAX_MESSAGE_CHARS / 5);
        for _ in 0..MAX_LINES {
            buf.info(T0, &full);
        }
        buf.record_outcome(&full);
        let out = buf.export(T0);
        // 500 lines of (timestamped, labelled, 240-char) text plus header.
        assert!(out.len() < 150_000, "export was {} bytes", out.len());
    }

    #[test]
    fn times_format_as_utc() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_time(T0), "2026-01-01 00:00:00 UTC");
        assert_eq!(format_time(T0 + 86_399), "2026-01-01 23:59:59 UTC");
        assert_eq!(format_time(1_709_164_800), "2024-02-29 00:00:00 UTC");
    }

    #[test]
    fn levels_have_stable_labels() {
        assert_eq!(Level::Info.label(), "INFO");
        assert_eq!(Level::Warn.label(), "WARN");
        assert_eq!(Level::Error.label(), "ERROR");
        assert_eq!(Level::Warn.to_string(), "WARN");
        // The shell contract: levels serialise lowercase.
        assert_eq!(serde_json::to_string(&Level::Error).unwrap(), "\"error\"");
    }
}
