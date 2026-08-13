use std::io::{self, Stdout};

use crossterm::cursor::{Hide, Show};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditorAction {
    None,
    Submit(String),
    CancelTask,
    Exit,
}

#[derive(Default)]
pub struct InputEditor {
    text: String,
    cursor: usize,
}

impl InputEditor {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn handle(&mut self, key: KeyEvent, task_active: bool) -> EditorAction {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return match key.code {
                KeyCode::Char('c') if task_active => EditorAction::CancelTask,
                KeyCode::Char('c') => {
                    self.text.clear();
                    self.cursor = 0;
                    EditorAction::None
                }
                KeyCode::Char('d') => EditorAction::Exit,
                _ => EditorAction::None,
            };
        }
        match key.code {
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.insert('\n');
                EditorAction::None
            }
            KeyCode::Enter => {
                if self.text.trim().is_empty() {
                    return EditorAction::None;
                }
                let submitted = std::mem::take(&mut self.text);
                self.cursor = 0;
                EditorAction::Submit(submitted)
            }
            KeyCode::Char(character) => {
                self.insert(character);
                EditorAction::None
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let previous = self.text[..self.cursor]
                        .char_indices()
                        .next_back()
                        .map_or(0, |(index, _)| index);
                    self.text.drain(previous..self.cursor);
                    self.cursor = previous;
                }
                EditorAction::None
            }
            KeyCode::Delete => {
                if self.cursor < self.text.len() {
                    let next = self.text[self.cursor..]
                        .char_indices()
                        .nth(1)
                        .map_or(self.text.len(), |(offset, _)| self.cursor + offset);
                    self.text.drain(self.cursor..next);
                }
                EditorAction::None
            }
            KeyCode::Left => {
                self.cursor = self.text[..self.cursor]
                    .char_indices()
                    .next_back()
                    .map_or(0, |(index, _)| index);
                EditorAction::None
            }
            KeyCode::Right => {
                if self.cursor < self.text.len() {
                    self.cursor = self.text[self.cursor..]
                        .char_indices()
                        .nth(1)
                        .map_or(self.text.len(), |(offset, _)| self.cursor + offset);
                }
                EditorAction::None
            }
            KeyCode::Home => {
                self.cursor = 0;
                EditorAction::None
            }
            KeyCode::End => {
                self.cursor = self.text.len();
                EditorAction::None
            }
            _ => EditorAction::None,
        }
    }

    fn insert(&mut self, character: char) {
        self.text.insert(self.cursor, character);
        self.cursor += character.len_utf8();
    }
}

pub trait TerminalControl {
    type Error;

    fn enter(&mut self) -> Result<(), Self::Error>;
    fn restore(&mut self) -> Result<(), Self::Error>;
}

pub struct TerminalOwner<C: TerminalControl> {
    control: C,
    restored: bool,
}

impl<C: TerminalControl> TerminalOwner<C> {
    pub fn enter(mut control: C) -> Result<Self, C::Error> {
        control.enter()?;
        Ok(Self {
            control,
            restored: false,
        })
    }

    pub fn restore(&mut self) -> Result<(), C::Error> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        self.control.restore()
    }
}

impl<C: TerminalControl> Drop for TerminalOwner<C> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub struct CrosstermControl {
    stdout: Stdout,
}

impl Default for CrosstermControl {
    fn default() -> Self {
        Self {
            stdout: io::stdout(),
        }
    }
}

impl TerminalControl for CrosstermControl {
    type Error = io::Error;

    fn enter(&mut self) -> Result<(), Self::Error> {
        enable_raw_mode()?;
        if let Err(error) = execute!(self.stdout, EnterAlternateScreen, Hide) {
            let _ = disable_raw_mode();
            return Err(error);
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Self::Error> {
        let screen = execute!(self.stdout, Show, LeaveAlternateScreen);
        let raw = disable_raw_mode();
        screen.and(raw)
    }
}
