//! Generic `IMAP`/`SMTP` client helpers.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use mailparse::{DispositionType, MailHeaderMap, ParsedMail};
use native_tls::{TlsConnector, TlsStream};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{EmailGenericError, EmailGenericResult};
use crate::types::{
    EmailAttachmentCandidate, EmailGenericConfig, EmailInboundMessage, EmailSeenUidCache,
};

const MAX_IMAP_LITERAL_BYTES: usize = 1_048_576;
const MAX_IMAP_RESPONSE_BYTES: usize = 1_048_576;
const MAX_IMAP_RESPONSE_LINES: usize = 4_096;
const MAX_INBOUND_POLL_BYTES: usize = 8 * MAX_IMAP_LITERAL_BYTES;
const MAX_INBOUND_POLL_MESSAGES: usize = 128;
const MAX_CURSOR_MAILBOX_CHARS: usize = 1_024;

/// A caller-owned checkpoint for one account, mailbox, and IMAP UID epoch.
/// It records handled messages, never a fetched-but-unpublished batch tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailInboundCursor {
    pub version: u8,
    pub account_fingerprint: String,
    pub mailbox: String,
    pub uid_validity: u32,
    pub last_uid: u32,
}

impl EmailInboundCursor {
    pub fn validate(&self) -> EmailGenericResult<()> {
        if self.version != 1
            || self.account_fingerprint.len() != 64
            || !self
                .account_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.mailbox.trim().is_empty()
            || self.mailbox.chars().count() > MAX_CURSOR_MAILBOX_CHARS
            || self
                .mailbox
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            || self.uid_validity == 0
        {
            return Err(EmailGenericError::Config(
                "Invalid inbound cursor fields or version".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn event_cursor(&self) -> String {
        format!(
            "v{}:{}:{}:{}",
            self.version, self.account_fingerprint, self.uid_validity, self.last_uid
        )
    }
}

/// An immutable fetch result. `cursor` describes the observed epoch and starting
/// position, not the last message in `messages`; only the caller can commit it.
#[derive(Debug)]
pub struct EmailInboundBatch {
    pub requested_cursor: Option<EmailInboundCursor>,
    pub cursor: EmailInboundCursor,
    pub messages: Vec<EmailInboundMessage>,
}

enum ImapStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl Read for ImapStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for ImapStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

impl ImapStream {
    fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.shutdown(Shutdown::Both),
            Self::Tls(stream) => stream.get_mut().shutdown(Shutdown::Both),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmailGenericClient {
    config: EmailGenericConfig,
}

impl EmailGenericClient {
    pub fn from_config(config: &EmailGenericConfig) -> EmailGenericResult<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    const fn imap_timeout(&self) -> Duration {
        Duration::from_millis(self.config.request_timeout_ms)
    }

    /// Quote a value for inclusion in an IMAP command as an RFC 3501
    /// `quoted` string.
    ///
    /// RFC 3501 Section 4.3 prohibits CR (`\r`), LF (`\n`), and NUL inside the
    /// `quoted` production; those bytes are protocol terminators and
    /// have no legal escape sequence. A permissive server that
    /// tokenizes bytes before validating quoting could otherwise be
    /// driven into running attacker-controlled commands embedded in the
    /// supposed quoted value (CRLF injection). Reject those bytes
    /// fail-closed rather than emit a malformed quoted string.
    fn quote_imap(value: &str) -> EmailGenericResult<String> {
        for &byte in value.as_bytes() {
            if matches!(byte, b'\r' | b'\n' | 0) {
                return Err(EmailGenericError::Config(
                    "IMAP argument must not contain CR, LF, or NUL bytes".into(),
                ));
            }
        }
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        Ok(format!("\"{escaped}\""))
    }

    fn connect_imap(&self) -> EmailGenericResult<BufReader<ImapStream>> {
        let address = format!("{}:{}", self.config.imap.host, self.config.imap.port);
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(self.imap_timeout()))?;
        stream.set_write_timeout(Some(self.imap_timeout()))?;
        if self.config.imap.tls {
            let tls = TlsConnector::new()?
                .connect(&self.config.imap.host, stream)
                .map_err(|error| match error {
                    native_tls::HandshakeError::Failure(error) => EmailGenericError::Tls(error),
                    native_tls::HandshakeError::WouldBlock(_) => {
                        EmailGenericError::Imap("IMAP TLS handshake would block".into())
                    }
                })?;
            Ok(BufReader::new(ImapStream::Tls(tls)))
        } else {
            Ok(BufReader::new(ImapStream::Plain(stream)))
        }
    }

    fn read_line<R: BufRead>(reader: &mut R) -> EmailGenericResult<String> {
        let mut line = Vec::new();
        reader
            .take((MAX_IMAP_RESPONSE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if line.len() > MAX_IMAP_RESPONSE_BYTES {
            return Err(EmailGenericError::Imap(
                "IMAP response line exceeds byte limit".into(),
            ));
        }
        if line
            .strip_suffix(b"\r\n")
            .is_none_or(|frame| frame.contains(&b'\r'))
        {
            return Err(EmailGenericError::Imap(
                "IMAP response is truncated or lacks CRLF framing".into(),
            ));
        }
        if line.contains(&0) {
            return Err(EmailGenericError::Imap(
                "IMAP response line contains NUL".into(),
            ));
        }
        String::from_utf8(line)
            .map_err(|_| EmailGenericError::Imap("IMAP response line is not UTF-8".into()))
    }

    fn account_response_bytes(total: &mut usize, additional: usize) -> EmailGenericResult<()> {
        *total = total.saturating_add(additional);
        if *total > MAX_IMAP_RESPONSE_BYTES {
            return Err(EmailGenericError::Imap(
                "IMAP response exceeds byte limit".into(),
            ));
        }
        Ok(())
    }

    /// Only the tagged status atom completes a command. Human-readable response
    /// text may contain "OK" even when the actual command status is NO or BAD.
    fn command_completed(tag: &str, line: &str) -> EmailGenericResult<bool> {
        let mut atoms = line.split_ascii_whitespace();
        match atoms.next() {
            Some(response_tag) if response_tag == tag => match atoms.next() {
                Some(status) if status.eq_ignore_ascii_case("OK") => Ok(true),
                Some(status)
                    if status.eq_ignore_ascii_case("NO") || status.eq_ignore_ascii_case("BAD") =>
                {
                    Err(EmailGenericError::Imap(
                        "IMAP server rejected the command".into(),
                    ))
                }
                _ => Err(EmailGenericError::Imap(
                    "Invalid IMAP command completion status".into(),
                )),
            },
            Some("*") => {
                if tag != "az"
                    && atoms
                        .next()
                        .is_some_and(|atom| atom.eq_ignore_ascii_case("BYE"))
                {
                    return Err(EmailGenericError::Imap(
                        "IMAP server closed the session".into(),
                    ));
                }
                Ok(false)
            }
            _ => Err(EmailGenericError::Imap(
                "Unexpected IMAP response tag or continuation".into(),
            )),
        }
    }

    fn run_imap_command(
        reader: &mut BufReader<ImapStream>,
        tag: &str,
        command: &str,
    ) -> EmailGenericResult<Vec<String>> {
        reader
            .get_mut()
            .write_all(format!("{tag} {command}\r\n").as_bytes())?;
        reader.get_mut().flush()?;
        let mut lines = Vec::new();
        let mut response_bytes = 0;
        for _ in 0..MAX_IMAP_RESPONSE_LINES {
            let line = Self::read_line(reader)?;
            Self::account_response_bytes(&mut response_bytes, line.len())?;
            let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
            let done = Self::command_completed(tag, &trimmed)?;
            if !done && Self::parse_imap_literal_len(&trimmed)?.is_some() {
                return Err(EmailGenericError::Imap(
                    "Unexpected literal in IMAP command response".into(),
                ));
            }
            lines.push(trimmed);
            if done {
                return Ok(lines);
            }
        }
        Err(EmailGenericError::Imap(
            "IMAP command response exceeds line limit".into(),
        ))
    }

    fn run_imap_fetch_literal(
        reader: &mut BufReader<ImapStream>,
        tag: &str,
        command: &str,
        expected_uid: u32,
    ) -> EmailGenericResult<Vec<u8>> {
        reader
            .get_mut()
            .write_all(format!("{tag} {command}\r\n").as_bytes())?;
        reader.get_mut().flush()?;
        let mut literal = None;
        let mut response_bytes = 0;
        for _ in 0..MAX_IMAP_RESPONSE_LINES {
            let line = Self::read_line(reader)?;
            Self::account_response_bytes(&mut response_bytes, line.len())?;
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if Self::command_completed(tag, trimmed)? {
                return literal.ok_or_else(|| {
                    EmailGenericError::Imap("IMAP FETCH did not include an RFC822 literal".into())
                });
            }
            if let Some(len) = Self::parse_imap_literal_len(trimmed)? {
                if len > MAX_IMAP_LITERAL_BYTES {
                    return Err(EmailGenericError::Imap(format!(
                        "IMAP FETCH literal exceeds {MAX_IMAP_LITERAL_BYTES} byte limit"
                    )));
                }
                if literal.is_some() {
                    return Err(EmailGenericError::Imap(
                        "IMAP FETCH returned multiple message literals".into(),
                    ));
                }
                let mut body = vec![0_u8; len];
                reader.read_exact(&mut body)?;
                // The rest of this FETCH response follows the literal bytes, not
                // a new response. UID may legally appear before or after BODY[].
                let trailer = Self::read_line(reader)?;
                Self::account_response_bytes(&mut response_bytes, trailer.len())?;
                if Self::parse_fetch_literal_uid(trimmed, &trailer)? != expected_uid {
                    return Err(EmailGenericError::Imap(
                        "IMAP FETCH returned a different UID".into(),
                    ));
                }
                literal = Some(body);
            }
        }
        Err(EmailGenericError::Imap(
            "IMAP FETCH response exceeds line limit".into(),
        ))
    }

    fn take_imap_atom(input: &str) -> EmailGenericResult<(&str, &str)> {
        let input = input.trim_start();
        let end = input
            .find(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '(' | ')'))
            .unwrap_or(input.len());
        if end == 0 {
            return Err(EmailGenericError::Imap(
                "Malformed IMAP FETCH attributes".into(),
            ));
        }
        Ok(input.split_at(end))
    }

    /// Parse only the response attributes requested by our UID/BODY.PEEK[]
    /// fetch, plus unsolicited FLAGS. Never infer a UID from message bytes or
    /// from a nested flag name, and require the FETCH list to close completely.
    fn parse_fetch_literal_uid(header: &str, trailer: &str) -> EmailGenericResult<u32> {
        let invalid = || EmailGenericError::Imap("Malformed IMAP FETCH literal response".into());
        let (marker, rest) = Self::take_imap_atom(header)?;
        let (sequence, rest) = Self::take_imap_atom(rest)?;
        let (kind, attributes) = Self::take_imap_atom(rest)?;
        if marker != "*"
            || sequence
                .parse::<u32>()
                .ok()
                .is_none_or(|sequence| sequence == 0)
            || !kind.eq_ignore_ascii_case("FETCH")
        {
            return Err(invalid());
        }
        let (prefix, _) = attributes.rsplit_once('{').ok_or_else(invalid)?;
        if !prefix
            .split_ascii_whitespace()
            .last()
            .is_some_and(|name| name.trim_start_matches('(').eq_ignore_ascii_case("BODY[]"))
        {
            return Err(invalid());
        }
        // NIL is a placeholder for the one literal already read by the caller.
        let metadata = format!("{prefix}NIL{trailer}");
        let mut remaining = metadata.trim().strip_prefix('(').ok_or_else(invalid)?;
        let mut uid = None;
        let mut body_seen = false;
        loop {
            remaining = remaining.trim_start();
            if let Some(tail) = remaining.strip_prefix(')') {
                if !tail.trim().is_empty() || !body_seen {
                    return Err(invalid());
                }
                return uid.ok_or_else(invalid);
            }
            let (name, rest) = Self::take_imap_atom(remaining)?;
            remaining = rest.trim_start();
            if name.eq_ignore_ascii_case("UID") {
                let (value, rest) = Self::take_imap_atom(remaining)?;
                let value = value.parse::<u32>().map_err(|_| invalid())?;
                if value == 0 || uid.replace(value).is_some() {
                    return Err(invalid());
                }
                remaining = rest;
            } else if name.eq_ignore_ascii_case("BODY[]") {
                let (value, rest) = Self::take_imap_atom(remaining)?;
                if value != "NIL" || body_seen {
                    return Err(invalid());
                }
                body_seen = true;
                remaining = rest;
            } else if name.eq_ignore_ascii_case("FLAGS") {
                let (flags, rest) = remaining
                    .strip_prefix('(')
                    .and_then(|flags| flags.split_once(')'))
                    .ok_or_else(invalid)?;
                if flags.chars().any(|ch| matches!(ch, '(' | '"' | '{')) {
                    return Err(invalid());
                }
                remaining = rest;
            } else {
                return Err(invalid());
            }
        }
    }

    fn parse_imap_literal_len(line: &str) -> EmailGenericResult<Option<usize>> {
        let Some(start) = line.rfind('{') else {
            return Ok(None);
        };
        if !line.ends_with('}') {
            return Ok(None);
        }
        let length = &line[start + 1..line.len() - 1];
        if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(EmailGenericError::Imap(
                "Invalid IMAP literal length".into(),
            ));
        }
        length.parse::<usize>().map(Some).map_err(|error| {
            EmailGenericError::Imap(format!("Invalid IMAP literal length: {error}"))
        })
    }

    fn imap_login_and_read<F, T>(&self, f: F) -> EmailGenericResult<T>
    where
        F: FnOnce(&mut BufReader<ImapStream>) -> EmailGenericResult<T>,
    {
        let mut reader = self.connect_imap()?;
        let greeting = Self::read_line(&mut reader)?;
        let mut greeting_atoms = greeting.split_ascii_whitespace();
        if greeting_atoms.next() != Some("*")
            || !greeting_atoms
                .next()
                .is_some_and(|status| status.eq_ignore_ascii_case("OK"))
        {
            return Err(EmailGenericError::Imap("Invalid IMAP greeting".into()));
        }
        let login = format!(
            "LOGIN {} {}",
            Self::quote_imap(&self.config.imap.username)?,
            Self::quote_imap(&self.config.imap.password)?
        );
        Self::run_imap_command(&mut reader, "a1", &login)?;
        let result = f(&mut reader)?;
        let _ = Self::run_imap_command(&mut reader, "az", "LOGOUT");
        let _ = reader.get_mut().shutdown();
        Ok(result)
    }

    fn parse_mailboxes(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .filter_map(|line| {
                if !line.starts_with("* LIST") {
                    return None;
                }
                let trimmed = line.trim();
                if trimmed.ends_with('"') {
                    let mut parts = trimmed.rsplitn(3, '"');
                    parts.next()?;
                    parts.next().map(std::string::ToString::to_string)
                } else {
                    trimmed
                        .rsplit(' ')
                        .next()
                        .map(std::string::ToString::to_string)
                }
            })
            .collect()
    }

    fn parse_search_uids(lines: &[String]) -> EmailGenericResult<Vec<u32>> {
        let mut result = None;
        for line in lines {
            let mut atoms = line.split_ascii_whitespace();
            if atoms.next() != Some("*")
                || !atoms
                    .next()
                    .is_some_and(|atom| atom.eq_ignore_ascii_case("SEARCH"))
            {
                continue;
            }
            if result.is_some() {
                return Err(EmailGenericError::Imap(
                    "IMAP command returned multiple SEARCH results".into(),
                ));
            }
            let mut uids = std::collections::BTreeSet::new();
            for atom in atoms {
                let uid = atom
                    .parse::<u32>()
                    .ok()
                    .filter(|uid| *uid != 0)
                    .ok_or_else(|| EmailGenericError::Imap("Invalid IMAP SEARCH UID".into()))?;
                uids.insert(uid);
            }
            result = Some(uids.into_iter().collect());
        }
        result.ok_or_else(|| EmailGenericError::Imap("IMAP command omitted SEARCH result".into()))
    }

    pub fn health(&self) -> EmailGenericResult<Value> {
        let mailboxes = self.list_mailboxes()?;
        Ok(json!({
            "status": "ok",
            "imap_host": self.config.imap.host,
            "smtp_host": self.config.smtp.host,
            "mailbox_count": mailboxes["mailboxes"].as_array().map_or(0, Vec::len),
        }))
    }

    pub fn list_mailboxes(&self) -> EmailGenericResult<Value> {
        self.imap_login_and_read(|reader| {
            let lines = Self::run_imap_command(reader, "a2", "LIST \"\" \"*\"")?;
            Ok(json!({ "mailboxes": Self::parse_mailboxes(&lines) }))
        })
    }

    pub fn search_messages(&self, mailbox: &str, query: &str) -> EmailGenericResult<Value> {
        if mailbox.trim().is_empty() || query.trim().is_empty() {
            return Err(EmailGenericError::Config(
                "mailbox and query must not be empty".into(),
            ));
        }
        self.imap_login_and_read(|reader| {
            let examine = format!("EXAMINE {}", Self::quote_imap(mailbox)?);
            Self::run_imap_command(reader, "a2", &examine)?;
            let search = format!("UID SEARCH TEXT {}", Self::quote_imap(query)?);
            let lines = Self::run_imap_command(reader, "a3", &search)?;
            Ok(json!({
                "mailbox": mailbox,
                "query": query,
                "uids": Self::parse_search_uids(&lines)?,
            }))
        })
    }

    /// Retrieve candidates without acknowledging them or setting provider
    /// \Seen flags. Callers observe UIDs only after publication or an explicit
    /// policy rejection. Any failed fetch aborts this session and leaves every
    /// candidate retryable on a fresh connection.
    pub fn fetch_unseen_inbound_messages(
        &self,
        mailbox: &str,
        seen_uids: &EmailSeenUidCache,
    ) -> EmailGenericResult<Vec<EmailInboundMessage>> {
        if mailbox.trim().is_empty() {
            return Err(EmailGenericError::Config(
                "mailbox must not be empty".into(),
            ));
        }
        self.imap_login_and_read(|reader| {
            let examine = format!("EXAMINE {}", Self::quote_imap(mailbox)?);
            Self::run_imap_command(reader, "a2", &examine)?;
            let search_lines = Self::run_imap_command(reader, "a3", "UID SEARCH UNSEEN")?;
            Self::fetch_inbound_candidates(reader, &search_lines, 0, Some(seen_uids))
        })
    }

    /// Bind progress to non-secret logical account identity. Password rotation
    /// must not change the identity, and credential material never enters it.
    pub(crate) fn inbound_account_fingerprint(
        config: &EmailGenericConfig,
        mailbox: &str,
    ) -> String {
        let identity = json!([
            "fcp.email-generic.inbound",
            1,
            config.imap.host.to_ascii_lowercase(),
            config.imap.port,
            config.imap.tls,
            config.imap.username,
            mailbox,
        ]);
        hex::encode(Sha256::digest(identity.to_string().as_bytes()))
    }

    fn parse_uid_validity(lines: &[String]) -> EmailGenericResult<u32> {
        let invalid = || EmailGenericError::Imap("Missing or invalid IMAP UIDVALIDITY".into());
        let mut uid_validity = None;
        for line in lines {
            let mut atoms = line.split_ascii_whitespace();
            let _tag = atoms.next();
            let status = atoms.next();
            let Some(code) = atoms.next() else {
                continue;
            };
            if !code.to_ascii_uppercase().starts_with("[UIDVALIDITY") {
                continue;
            }
            if !code.eq_ignore_ascii_case("[UIDVALIDITY")
                || !status.is_some_and(|status| status.eq_ignore_ascii_case("OK"))
            {
                return Err(invalid());
            }
            let value = atoms
                .next()
                .and_then(|value| value.strip_suffix(']'))
                .ok_or_else(invalid)?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            let value = value.parse::<u32>().map_err(|_| invalid())?;
            if value == 0 || uid_validity.replace(value).is_some() {
                return Err(invalid());
            }
        }
        uid_validity.ok_or_else(invalid)
    }

    /// Read one bounded batch after a verified epoch checkpoint. A changed
    /// UIDVALIDITY restarts the scan; fetching never advances the checkpoint.
    pub fn fetch_inbound_batch(
        &self,
        mailbox: &str,
        cursor: Option<&EmailInboundCursor>,
    ) -> EmailGenericResult<EmailInboundBatch> {
        if mailbox.trim().is_empty() || mailbox.chars().count() > MAX_CURSOR_MAILBOX_CHARS {
            return Err(EmailGenericError::Config(
                "Invalid inbound cursor mailbox".into(),
            ));
        }
        let quoted_mailbox = Self::quote_imap(mailbox)?;
        let account_fingerprint = Self::inbound_account_fingerprint(&self.config, mailbox);
        if let Some(cursor) = cursor {
            cursor.validate()?;
            if cursor.mailbox != mailbox || cursor.account_fingerprint != account_fingerprint {
                return Err(EmailGenericError::Config(
                    "Inbound cursor belongs to a different account or mailbox".into(),
                ));
            }
        }
        self.imap_login_and_read(|reader| {
            let lines = Self::run_imap_command(reader, "a2", &format!("EXAMINE {quoted_mailbox}"))?;
            let uid_validity = Self::parse_uid_validity(&lines)?;
            let last_uid = cursor
                .filter(|cursor| cursor.uid_validity == uid_validity)
                .map_or(0, |cursor| cursor.last_uid);
            let starting_cursor = EmailInboundCursor {
                version: 1,
                account_fingerprint,
                mailbox: mailbox.to_owned(),
                uid_validity,
                last_uid,
            };
            let messages = if let Some(next_uid) = last_uid.checked_add(1) {
                let search = if last_uid == 0 {
                    "UID SEARCH UNSEEN".to_owned()
                } else {
                    format!("UID SEARCH UNSEEN UID {next_uid}:*")
                };
                let lines = Self::run_imap_command(reader, "a3", &search)?;
                Self::fetch_inbound_candidates(reader, &lines, last_uid, None)?
            } else {
                // The epoch has exhausted its UID space. EXAMINE above still
                // detects a changed epoch before this no-op path is selected.
                Vec::new()
            };
            Ok(EmailInboundBatch {
                requested_cursor: cursor.cloned(),
                cursor: starting_cursor,
                messages,
            })
        })
    }

    fn fetch_inbound_candidates(
        reader: &mut BufReader<ImapStream>,
        search_lines: &[String],
        after_uid: u32,
        seen_uids: Option<&EmailSeenUidCache>,
    ) -> EmailGenericResult<Vec<EmailInboundMessage>> {
        let mut messages = Vec::new();
        let mut fetched_bytes = 0_usize;
        for uid in Self::parse_search_uids(search_lines)? {
            // IMAP n:* includes the highest existing UID even when n is larger.
            // Enforce the lower bound independently of the server's SEARCH.
            if uid <= after_uid {
                continue;
            }
            let uid_text = uid.to_string();
            if seen_uids.is_some_and(|seen| seen.contains(&uid_text)) {
                continue;
            }
            let fetch = format!("UID FETCH {uid} (UID BODY.PEEK[])");
            let raw = Self::run_imap_fetch_literal(reader, &format!("f{uid}"), &fetch, uid)?;
            fetched_bytes = fetched_bytes.saturating_add(raw.len());
            messages.push(Self::parse_inbound_message(uid_text, &raw)?);
            if fetched_bytes >= MAX_INBOUND_POLL_BYTES
                || messages.len() >= MAX_INBOUND_POLL_MESSAGES
            {
                break;
            }
        }
        Ok(messages)
    }

    pub fn parse_inbound_message(
        uid: impl Into<String>,
        raw: &[u8],
    ) -> EmailGenericResult<EmailInboundMessage> {
        let parsed = mailparse::parse_mail(raw).map_err(|error| Self::mail_parse_error(&error))?;
        let sender = parsed
            .headers
            .get_first_value("From")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| EmailGenericError::Imap("RFC822 message is missing From".into()))?;
        let headers = parsed
            .headers
            .iter()
            .map(|header| (header.get_key(), header.get_value()))
            .collect::<Vec<_>>();
        Ok(EmailInboundMessage {
            uid: uid.into(),
            sender,
            headers,
            subject: parsed
                .headers
                .get_first_value("Subject")
                .unwrap_or_default(),
            body: Self::extract_text_body(&parsed)?,
            message_id: parsed.headers.get_first_value("Message-ID"),
            in_reply_to: parsed.headers.get_first_value("In-Reply-To"),
            references: parsed.headers.get_first_value("References"),
            attachments: Self::extract_attachments(&parsed)?,
        })
    }

    fn mail_parse_error(error: &mailparse::MailParseError) -> EmailGenericError {
        EmailGenericError::Imap(format!("Failed to parse RFC822 message: {error}"))
    }

    fn extract_text_body(parsed: &ParsedMail<'_>) -> EmailGenericResult<String> {
        if let Some(body) = Self::find_body_part(parsed, "text/plain")? {
            return Ok(body);
        }
        if let Some(body) = Self::find_body_part(parsed, "text/html")? {
            return Ok(Self::strip_html_tags(&body));
        }
        Ok(String::new())
    }

    fn find_body_part(
        part: &ParsedMail<'_>,
        media_type: &str,
    ) -> EmailGenericResult<Option<String>> {
        if part.subparts.is_empty()
            && part.ctype.mimetype.eq_ignore_ascii_case(media_type)
            && Self::part_filename(part).is_none()
            && !matches!(
                part.get_content_disposition().disposition,
                DispositionType::Attachment
            )
        {
            return part
                .get_body()
                .map(Some)
                .map_err(|error| Self::mail_parse_error(&error));
        }
        for subpart in &part.subparts {
            if let Some(body) = Self::find_body_part(subpart, media_type)? {
                return Ok(Some(body));
            }
        }
        Ok(None)
    }

    fn extract_attachments(
        parsed: &ParsedMail<'_>,
    ) -> EmailGenericResult<Vec<EmailAttachmentCandidate>> {
        let mut attachments = Vec::new();
        for part in parsed.parts() {
            let Some(filename) = Self::part_filename(part) else {
                continue;
            };
            let size_bytes = part
                .get_body_raw()
                .map_err(|error| Self::mail_parse_error(&error))?
                .len();
            attachments.push(EmailAttachmentCandidate {
                filename,
                media_type: part.ctype.mimetype.clone(),
                size_bytes,
            });
        }
        Ok(attachments)
    }

    fn part_filename(part: &ParsedMail<'_>) -> Option<String> {
        let disposition = part.get_content_disposition();
        disposition
            .params
            .get("filename")
            .or_else(|| part.ctype.params.get("name"))
            .filter(|value| !value.trim().is_empty())
            .cloned()
    }

    fn strip_html_tags(html: &str) -> String {
        let mut text = String::new();
        let mut in_tag = false;
        let mut chars = html.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '<' => {
                    if let Some(&next_ch) = chars.peek() {
                        if next_ch.is_ascii_alphabetic() || next_ch == '/' {
                            in_tag = true;
                            continue;
                        }
                    }
                    if !in_tag {
                        text.push(ch);
                    }
                }
                '>' => {
                    if in_tag {
                        in_tag = false;
                    } else {
                        text.push(ch);
                    }
                }
                _ if !in_tag => text.push(ch),
                _ => {}
            }
        }
        text.replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
    }

    pub fn send_message(
        &self,
        to: &[String],
        subject: &str,
        body: &str,
        cc: &[String],
    ) -> EmailGenericResult<Value> {
        if to.is_empty() {
            return Err(EmailGenericError::Config(
                "at least one recipient is required".into(),
            ));
        }
        let from = Mailbox::new(
            self.config.smtp.from_name.clone(),
            self.config
                .smtp
                .from_address
                .parse::<lettre::Address>()
                .map_err(|error| EmailGenericError::Address(error.to_string()))?,
        );
        let mut builder = Message::builder().from(from).subject(subject);
        for recipient in to {
            builder = builder.to(recipient
                .parse::<Mailbox>()
                .map_err(|error| EmailGenericError::Address(error.to_string()))?);
        }
        for recipient in cc {
            builder = builder.cc(recipient
                .parse::<Mailbox>()
                .map_err(|error| EmailGenericError::Address(error.to_string()))?);
        }
        let message = builder
            .body(body.to_string())
            .map_err(|error| EmailGenericError::Smtp(error.to_string()))?;
        let creds = Credentials::new(
            self.config.smtp.username.clone(),
            self.config.smtp.get_password(),
        );
        let mailer = if self.config.smtp.starttls {
            SmtpTransport::relay(&self.config.smtp.host)
                .map_err(|error| EmailGenericError::Smtp(error.to_string()))?
                .port(self.config.smtp.port)
                .credentials(creds)
                .build()
        } else {
            SmtpTransport::builder_dangerous(&self.config.smtp.host)
                .port(self.config.smtp.port)
                .credentials(creds)
                .build()
        };
        mailer
            .send(&message)
            .map_err(|error| EmailGenericError::Smtp(error.to_string()))?;
        Ok(json!({
            "status": "sent",
            "to": to,
            "cc": cc,
            "subject": subject,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> EmailGenericConfig {
        EmailGenericConfig::from_value(serde_json::json!({
            "imap": {
                "host": "imap.example.com",
                "username": "user@example.com",
                "password": "secret"
            },
            "smtp": {
                "host": "smtp.example.com",
                "username": "user@example.com",
                "password": "secret",
                "from_address": "user@example.com"
            }
        }))
        .expect("config should parse")
    }

    #[test]
    fn parse_mailboxes_extracts_last_quoted_token() {
        let mailboxes = EmailGenericClient::parse_mailboxes(&[
            "* LIST (\\HasNoChildren) \"/\" \"INBOX\"".into(),
            "a2 OK LIST completed".into(),
        ]);
        assert_eq!(mailboxes, vec!["INBOX"]);
    }

    #[test]
    fn parse_search_uids_extracts_uid_list() {
        let uids = EmailGenericClient::parse_search_uids(&[
            "* SEARCH 2 5 8".into(),
            "a3 OK SEARCH completed".into(),
        ])
        .expect("valid SEARCH result");
        assert_eq!(uids, vec![2, 5, 8]);
    }

    #[test]
    fn search_results_reject_invalid_or_missing_uids_and_deduplicate() {
        for lines in [
            vec!["* SEARCH 0".into()],
            vec!["* SEARCH 11 invalid 12".into()],
            vec!["* SEARCH 4294967296".into()],
            vec!["a3 OK completed without SEARCH".into()],
            vec!["* SEARCH 11".into(), "* SEARCH 12".into()],
        ] {
            assert!(EmailGenericClient::parse_search_uids(&lines).is_err());
        }
        assert!(
            EmailGenericClient::parse_search_uids(&["* SEARCH".into()])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            EmailGenericClient::parse_search_uids(&["* SEARCH 12 11 12".into()]).unwrap(),
            vec![11, 12]
        );
    }

    #[test]
    fn imap_completion_requires_the_exact_tag_and_status_atom() {
        assert!(EmailGenericClient::command_completed("f11", "f11 OK completed").unwrap());
        assert!(EmailGenericClient::command_completed("f11", "f11 ok completed").unwrap());
        assert!(!EmailGenericClient::command_completed("f11", "* 3 EXISTS").unwrap());
        for line in [
            "f11 NO FETCH failed, other commands are OK",
            "f11 BAD not OK",
            "f11 OKAY",
            "f12 OK completed",
            "+ continue",
            "* BYE closing",
        ] {
            assert!(EmailGenericClient::command_completed("f11", line).is_err());
        }
    }

    #[test]
    fn imap_fetch_uid_is_bound_to_the_complete_literal_response() {
        for (header, trailer) in [
            ("* 1 FETCH (UID 11 BODY[] {42}", ")\r\n"),
            ("* 1 FETCH (BODY[] {42}", " UID 11)\r\n"),
            ("* 1 FETCH (FLAGS (\\Seen) UID 11 BODY[] {42}", ")\r\n"),
            ("* 1 FETCH (BODY[] {42}", " FLAGS (UID) UID 11)\r\n"),
        ] {
            assert_eq!(
                EmailGenericClient::parse_fetch_literal_uid(header, trailer).unwrap(),
                11
            );
        }
        for (header, trailer) in [
            ("* 1 FETCH (BODY[] {42}", ")\r\n"),
            ("* 1 FETCH (UID 0 BODY[] {42}", ")\r\n"),
            ("* 1 FETCH (UID 11 BODY[] {42}", " UID 12)\r\n"),
            ("* 1 FETCH (UID 11 BODY[HEADER] {42}", ")\r\n"),
            ("* 1 FETCH (UID 11 BODY[] {42}", "f11 OK completed\r\n"),
            ("* 1 FETCH (UID 11 BODY[] {42}", ") unexpected\r\n"),
            ("* 1 FETCH (FLAGS (UID 11) BODY[] {42}", ")\r\n"),
            ("* 0 FETCH (UID 11 BODY[] {42}", ")\r\n"),
        ] {
            assert!(EmailGenericClient::parse_fetch_literal_uid(header, trailer).is_err());
        }
    }

    #[test]
    fn imap_lines_require_bounded_complete_crlf_frames() {
        for bytes in [
            b"".as_slice(),
            b"* OK missing terminator",
            b"* OK bare newline\n",
            b"* OK embedded\rcarriage return\r\n",
            b"* OK nul\0byte\r\n",
        ] {
            assert!(EmailGenericClient::read_line(&mut std::io::Cursor::new(bytes)).is_err());
        }
        let oversized = vec![b'x'; MAX_IMAP_RESPONSE_BYTES + 1];
        assert!(EmailGenericClient::read_line(&mut std::io::Cursor::new(oversized)).is_err());
        assert_eq!(
            EmailGenericClient::read_line(&mut std::io::Cursor::new(b"* OK ready\r\n")).unwrap(),
            "* OK ready\r\n"
        );
    }

    #[test]
    fn quote_imap_escapes_backslashes_and_quotes() {
        let _ = config();
        assert_eq!(
            EmailGenericClient::quote_imap("ab\\\"cd").unwrap(),
            "\"ab\\\\\\\"cd\""
        );
    }

    #[test]
    fn uid_validity_requires_one_complete_nonzero_epoch() {
        for line in [
            "* OK [UIDVALIDITY 42] stable",
            "* ok [uidvalidity 4294967295] stable",
        ] {
            assert!(EmailGenericClient::parse_uid_validity(&[line.into()]).is_ok());
        }
        for lines in [
            vec!["a2 OK [READ-ONLY] opened".into()],
            vec!["* OK [UIDVALIDITY 0] invalid".into()],
            vec!["* OK [UIDVALIDITY 4294967296] overflow".into()],
            vec!["* OK [UIDVALIDITY +42] invalid".into()],
            vec!["* OK [UIDVALIDITY 42 missing bracket".into()],
            vec![
                "* OK [UIDVALIDITY 42] stable".into(),
                "* OK [UIDVALIDITY 42] duplicate".into(),
            ],
            vec![
                "* OK [UIDVALIDITY42] malformed".into(),
                "* OK [UIDVALIDITY 42] stable".into(),
            ],
            vec![
                "* NO [UIDVALIDITY 42] invalid status".into(),
                "* OK [UIDVALIDITY 42] stable".into(),
            ],
        ] {
            assert!(
                EmailGenericClient::parse_uid_validity(&lines).is_err(),
                "accepted {lines:?}"
            );
        }
    }

    #[test]
    fn cursor_identity_binds_nonsecret_account_and_mailbox_but_not_passwords() {
        let config = config();
        let fingerprint = EmailGenericClient::inbound_account_fingerprint(&config, "INBOX");
        let mut rotated = config.clone();
        rotated.imap.password = "rotated IMAP secret".into();
        rotated.smtp.password = "rotated SMTP secret".into();
        assert_eq!(
            fingerprint,
            EmailGenericClient::inbound_account_fingerprint(&rotated, "INBOX")
        );
        assert_ne!(
            fingerprint,
            EmailGenericClient::inbound_account_fingerprint(&config, "Archive")
        );
        for variant in 0..4 {
            let mut different = config.clone();
            match variant {
                0 => different.imap.host = "other.example.com".into(),
                1 => different.imap.port = 143,
                2 => different.imap.username = "other@example.com".into(),
                _ => different.imap.tls = false,
            }
            assert_ne!(
                fingerprint,
                EmailGenericClient::inbound_account_fingerprint(&different, "INBOX")
            );
        }
    }

    #[test]
    fn cursor_fields_are_versioned_bounded_and_reject_unknown_data() {
        let cursor = EmailInboundCursor {
            version: 1,
            account_fingerprint: EmailGenericClient::inbound_account_fingerprint(
                &config(),
                "INBOX",
            ),
            mailbox: "INBOX".into(),
            uid_validity: 42,
            last_uid: u32::MAX,
        };
        cursor.validate().expect("maximum handled UID is valid");
        assert!(cursor.event_cursor().ends_with(":42:4294967295"));
        for (field, value) in [
            ("version", json!(2)),
            ("account_fingerprint", json!("g".repeat(64))),
            ("mailbox", json!("x".repeat(1025))),
            ("mailbox", json!("INBOX\r\nLOGOUT")),
            ("uid_validity", json!(0)),
        ] {
            let mut value_cursor = serde_json::to_value(&cursor).unwrap();
            value_cursor[field] = value;
            let invalid: EmailInboundCursor = serde_json::from_value(value_cursor).unwrap();
            assert!(invalid.validate().is_err());
        }
        let mut unknown = serde_json::to_value(&cursor).unwrap();
        unknown["password"] = json!("must not enter a checkpoint");
        assert!(serde_json::from_value::<EmailInboundCursor>(unknown).is_err());
        let mut unicode = cursor;
        unicode.mailbox = "é".repeat(1024);
        assert!(
            unicode.validate().is_ok(),
            "mailbox bound matches JSON Schema character count"
        );
    }

    /// RFC 3501 Section 4.3 forbids CR, LF, and NUL inside a `quoted` IMAP
    /// string. A permissive server that tokenizes bytes before
    /// validating quoting could let an attacker who controls the
    /// `mailbox` or `query` argument inject extra IMAP commands via
    /// `\r\n<command>`. The fail-closed variant rejects those bytes.
    #[test]
    fn quote_imap_rejects_crlf_and_nul() {
        for inject in [
            "INBOX\r\na999 LOGOUT",
            "INBOX\nfoo",
            "INBOX\rfoo",
            "INBOX\0LOGOUT",
        ] {
            let err =
                EmailGenericClient::quote_imap(inject).expect_err("CR/LF/NUL must be rejected");
            assert!(
                matches!(err, EmailGenericError::Config(_)),
                "unexpected error variant for {inject:?}: {err:?}"
            );
        }
    }

    #[test]
    fn quote_imap_accepts_non_control_characters() {
        assert!(EmailGenericClient::quote_imap("INBOX").is_ok());
        assert!(EmailGenericClient::quote_imap("Important/Travel").is_ok());
        assert!(EmailGenericClient::quote_imap("Special Folder").is_ok());
    }

    #[test]
    fn parse_imap_literal_len_accepts_fetch_literal_marker() {
        assert_eq!(
            EmailGenericClient::parse_imap_literal_len("* 1 FETCH (RFC822 {42}").unwrap(),
            Some(42)
        );
        assert_eq!(
            EmailGenericClient::parse_imap_literal_len("* SEARCH 2 5 8").unwrap(),
            None
        );
    }

    #[test]
    fn parse_inbound_message_extracts_headers_body_and_attachment_metadata() {
        let raw = concat!(
            "From: Human <human@example.com>\r\n",
            "Subject: =?utf-8?Q?Deploy_ready?=\r\n",
            "Message-ID: <msg-1@example.com>\r\n",
            "In-Reply-To: <parent@example.com>\r\n",
            "References: <root@example.com> <parent@example.com>\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "green\r\n",
            "--b\r\n",
            "Content-Type: application/pdf; name=\"plan.pdf\"\r\n",
            "Content-Disposition: attachment; filename=\"plan.pdf\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "cGxhbg==\r\n",
            "--b--\r\n",
        );
        let message = EmailGenericClient::parse_inbound_message("99", raw.as_bytes()).unwrap();
        assert_eq!(message.uid, "99");
        assert_eq!(message.sender, "Human <human@example.com>");
        assert_eq!(message.subject, "Deploy ready");
        assert_eq!(message.body.trim(), "green");
        assert_eq!(message.message_id.as_deref(), Some("<msg-1@example.com>"));
        assert_eq!(message.attachments.len(), 1);
        assert_eq!(message.attachments[0].filename, "plan.pdf");
        assert_eq!(message.attachments[0].media_type, "application/pdf");
        assert_eq!(message.attachments[0].size_bytes, 4);
    }

    #[test]
    fn parse_inbound_message_prefers_plain_text_over_html() {
        let raw = concat!(
            "From: human@example.com\r\n",
            "Subject: Body choice\r\n",
            "Content-Type: multipart/alternative; boundary=\"alt\"\r\n",
            "\r\n",
            "--alt\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<p>html</p>\r\n",
            "--alt\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "plain\r\n",
            "--alt--\r\n",
        );
        let message = EmailGenericClient::parse_inbound_message("7", raw.as_bytes()).unwrap();
        assert_eq!(message.body.trim(), "plain");
    }
}
