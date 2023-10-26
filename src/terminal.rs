/*
 * Copyright 2023 Oxide Computer Company
 */

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, BytesMut};

pub struct Terminal {
    buf: BytesMut,
    input: BytesMut,
    hostname: String,
    state: State,
    output: Option<Vec<String>>,
    cmd: Option<String>,
    csi_d: bool,
}

#[derive(Debug)]
enum State {
    Startup,
    StartupHostname,
    Error(String),
    AtPrompt,
    Output,
    OutputCr,
    OutputEscape,
    OutputCsi,
}

impl Terminal {
    pub fn new() -> Terminal {
        Terminal {
            state: State::Startup,
            buf: Default::default(),
            input: Default::default(),
            hostname: "".to_string(),
            output: None,
            cmd: None,
            csi_d: false,
        }
    }

    pub fn ingest(&mut self, bytes: &[u8]) {
        self.input.put(bytes);
    }

    pub fn start_command(&mut self, cmd: &str) -> Result<()> {
        match &self.state {
            State::Error(e) => {
                bail!("{e}");
            }
            s @ (State::Startup
            | State::StartupHostname
            | State::Output
            | State::OutputCr
            | State::OutputEscape
            | State::OutputCsi) => {
                bail!("invalid state {s:?} for command start");
            }
            State::AtPrompt => {
                self.state = State::Output;
                self.output = Some(Default::default());
                self.cmd = Some(cmd.into());
                Ok(())
            }
        }
    }

    pub fn at_prompt(&self) -> bool {
        matches!(self.state, State::AtPrompt)
    }

    pub fn peek_prompt(&self) -> String {
        String::from_utf8_lossy(&self.buf).to_string()
    }

    pub fn has_output(&mut self) -> bool {
        match &self.state {
            State::AtPrompt => self.output.is_some(),
            _ => false,
        }
    }

    pub fn take_output(&mut self) -> Result<Vec<String>> {
        match &self.state {
            State::Error(e) => {
                bail!("{e}");
            }
            s @ (State::Startup
            | State::StartupHostname
            | State::Output
            | State::OutputCr
            | State::OutputEscape
            | State::OutputCsi) => {
                bail!("invalid state {s:?} for output fetch");
            }
            State::AtPrompt => match self.output.take() {
                Some(mut x) => {
                    if x.is_empty() || x[0] != self.cmd.as_deref().unwrap() {
                        bail!("expected to see echoed command, not {x:?}");
                    }

                    x.remove(0);
                    self.cmd.take().unwrap();

                    Ok(x)
                }
                None => bail!("no output to take"),
            },
        }
    }

    pub fn process(&mut self) -> Result<bool> {
        match &self.state {
            State::Error(e) => {
                bail!("{e}");
            }
            State::Startup => {
                /*
                 * Waiting for the expected pre-amble:
                 *  \r\n\r\r\n\r\n\r\n
                 */
                const PREAMBLE: &[u8] = b"\r\n\r\r\n\r\n\r\n";

                /*
                 * Confirm that everything so far matches the preamble.
                 */
                for i in 0..PREAMBLE.len().min(self.input.len()) {
                    if PREAMBLE[i] != self.input[i] {
                        let e =
                            format!("unexpected preamble: {:?}", self.input,);
                        self.state = State::Error(e.to_string());
                        bail!("{e}");
                    }
                }

                if self.input.len() >= PREAMBLE.len() {
                    println!("TERMINAL: got preamble");
                    self.state = State::StartupHostname;
                    self.buf.clear();
                    self.input.advance(PREAMBLE.len());
                    return Ok(true);
                }

                Ok(false)
            }
            State::StartupHostname => {
                if self.input.is_empty() {
                    return Ok(false);
                }

                let b = self.input[0];
                if b == b'#' {
                    /*
                     * This is the end of the prompt.
                     */
                    match String::from_utf8(self.buf.to_vec()) {
                        Ok(s) => {
                            println!("TERMINAL: got hostname {s:?}");
                            self.hostname = s;
                            self.state = State::AtPrompt;
                            self.buf.clear();
                            self.input.advance(1);
                            return Ok(true);
                        }
                        Err(e) => {
                            let e = format!(
                                "invalid UTF-8 in prompt: {:?}: {e}",
                                self.buf,
                            );
                            self.state = State::Error(e.to_string());
                            bail!("{e}");
                        }
                    }
                }

                if !b.is_ascii_alphanumeric() && b != b'-' && b != b'_' {
                    let e = format!(
                        "unexpected initial prompt byte: {:?}, {:?}",
                        self.buf, self.input,
                    );
                    self.state = State::Error(e.to_string());
                    bail!("{e}");
                }

                self.buf.put_u8(b);
                self.input.advance(1);
                Ok(true)
            }
            State::AtPrompt => {
                if self.input.is_empty() {
                    return Ok(false);
                }

                /*
                 * We do not expect any output when at the prompt, unless we are
                 * sending a command.
                 */
                let e = format!(
                    "unexpected output bytes while at prompt: {:?}",
                    self.input,
                );
                self.state = State::Error(e.to_string());
                bail!("{e}");
            }
            State::Output => {
                if self.input.is_empty() {
                    return Ok(false);
                }

                let b = self.input[0];

                /*
                 * Wait for the prompt to show up at the beginning of a line.
                 * The prompt may have several different shapes, depending on
                 * the current session mode.
                 */
                for prmode in [
                    None,
                    Some("config"),
                    Some("config-pubkey-chain"),
                    Some("config-pubkey-key"),
                    Some("config-if"),
                    Some("config-vlan"),
                ] {
                    let p = if let Some(prmode) = prmode {
                        format!("{}({prmode})", self.hostname)
                    } else {
                        self.hostname.to_string()
                    };
                    if self.buf.len() == p.as_bytes().len() {
                        if &self.buf[0..p.as_bytes().len()] == p.as_bytes()
                            && b == b'#'
                        {
                            println!(
                                "TERMINAL: back to {} prompt",
                                prmode
                                    .unwrap_or("ENABLE")
                                    .replace("-", " ")
                                    .to_ascii_uppercase()
                            );
                            self.buf.clear();
                            self.csi_d = false;
                            self.state = State::AtPrompt;
                            self.input.advance(1);
                            return Ok(true);
                        }
                    }
                }

                if b == b'\r' {
                    self.csi_d = false;
                    self.state = State::OutputCr;
                    self.input.advance(1);
                    return Ok(true);
                }

                if b == 0x1b {
                    /*
                     * Don't clear the CSI D bit here, because this may be a
                     * follow-up CSI K sequence.
                     */
                    self.state = State::OutputEscape;
                    self.input.advance(1);
                    return Ok(true);
                }

                if b.is_ascii_control() {
                    let e = format!(
                        "unexpected control characters: {:?}",
                        self.input,
                    );
                    self.state = State::Error(e.to_string());
                    bail!("{e}");
                }

                self.csi_d = false;
                self.buf.put_u8(b);
                self.input.advance(1);
                Ok(true)
            }
            State::OutputEscape => {
                if self.input.is_empty() {
                    return Ok(false);
                }

                let b = self.input[0];
                if b == b'[' {
                    self.state = State::OutputCsi;
                    self.input.advance(1);
                    return Ok(true);
                }

                let e = format!("unexpected escape before: {:?}", self.input);
                self.state = State::Error(e.to_string());
                bail!("{e}");
            }
            State::OutputCsi => {
                if self.input.is_empty() {
                    return Ok(false);
                }

                let b = self.input[0];
                if b == b'D' {
                    /*
                     * The CSI D sequence instructs the terminal to move the
                     * cursor back one cell.  The switch seems to emit a large
                     * number of these in a row sometimes in an attempt to, I
                     * suppose, move back to the leftmost column?  We'll note
                     * that we have seen a CSI D on this line, but do nothing
                     * else.
                     */
                    self.csi_d = true;
                    self.state = State::Output;
                    self.input.advance(1);
                    return Ok(true);
                }

                if b == b'K' {
                    /*
                     * The CSI K sequence instructs the terminal to erase from
                     * the current cursor position rightward.  If the cursor is
                     * in the leftmost column, that will have the effect of
                     * clearing the current line.  If we have previously seen a
                     * CSI D, we assume that the intent was to clear the whole
                     * line.
                     */
                    if !self.csi_d {
                        let e = format!(
                            "CSI K after {:?} with no previous CSI D",
                            String::from_utf8_lossy(&self.buf),
                        );
                        self.state = State::Error(e.to_string());
                        bail!("{e}");
                    }
                    self.buf.clear();
                    self.state = State::Output;
                    self.csi_d = false;
                    self.input.advance(1);
                    return Ok(true);
                }

                let e = format!("unexpected seq after CSI: {:?}", self.input);
                self.state = State::Error(e.to_string());
                bail!("{e}");
            }
            State::OutputCr => {
                if self.input.is_empty() {
                    return Ok(false);
                }

                let b = self.input[0];
                if b == b'\n' {
                    /*
                     * This is a CRLF line ending.
                     */
                    match String::from_utf8(self.buf.to_vec()) {
                        Ok(s) => {
                            self.output.as_mut().unwrap().push(s);
                            self.state = State::Output;
                            self.buf.clear();
                            self.input.advance(1);
                            return Ok(true);
                        }
                        Err(e) => {
                            let e = format!(
                                "invalid UTF-8 in prompt: {:?}: {e}",
                                self.buf,
                            );
                            self.state = State::Error(e.to_string());
                            bail!("{e}");
                        }
                    }
                }

                /*
                 * If there was no line feed after the carriage return, we
                 * assume the switch is trying to erase the contents of the
                 * current line -- which may be empty!.
                 */
                if !self.buf.is_empty() {
                    println!(
                        "WARNING: switch erased line contents? {:?}",
                        self.buf
                    );
                    self.buf.clear();
                }

                self.state = State::Output;
                Ok(true)
            }
        }
    }
}
