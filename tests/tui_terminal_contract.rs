use std::sync::{Arc, Mutex};

use carl::tui::terminal::{EditorAction, InputEditor, TerminalControl, TerminalOwner};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[test]
fn input_editor_handles_submit_multiline_cancel_clear_exit_and_unicode() {
    let mut editor = InputEditor::default();
    for character in ['h', 'é', 'l', 'p'] {
        assert_eq!(
            editor.handle(key(KeyCode::Char(character), KeyModifiers::NONE), false),
            EditorAction::None
        );
    }
    assert_eq!(
        editor.handle(key(KeyCode::Enter, KeyModifiers::SHIFT), false),
        EditorAction::None
    );
    assert!(editor.text().contains('\n'));
    assert_eq!(
        editor.handle(key(KeyCode::Enter, KeyModifiers::NONE), false),
        EditorAction::Submit("hélp\n".to_owned())
    );
    editor.handle(key(KeyCode::Char('x'), KeyModifiers::NONE), false);
    assert_eq!(
        editor.handle(key(KeyCode::Char('c'), KeyModifiers::CONTROL), false),
        EditorAction::None
    );
    assert!(editor.text().is_empty());
    assert_eq!(
        editor.handle(key(KeyCode::Char('c'), KeyModifiers::CONTROL), true),
        EditorAction::CancelTask
    );
    assert_eq!(
        editor.handle(key(KeyCode::Char('d'), KeyModifiers::CONTROL), false),
        EditorAction::Exit
    );
}

#[test]
fn terminal_owner_restores_exactly_once_on_drop_or_explicit_restore() {
    let log = Arc::new(Mutex::new(Vec::new()));
    {
        let mut owner = TerminalOwner::enter(FakeControl(Arc::clone(&log))).unwrap();
        owner.restore().unwrap();
        owner.restore().unwrap();
    }
    assert_eq!(&*log.lock().unwrap(), &["enter", "restore"]);
    log.lock().unwrap().clear();
    {
        let _owner = TerminalOwner::enter(FakeControl(Arc::clone(&log))).unwrap();
    }
    assert_eq!(&*log.lock().unwrap(), &["enter", "restore"]);
}

fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

struct FakeControl(Arc<Mutex<Vec<&'static str>>>);

impl TerminalControl for FakeControl {
    type Error = std::convert::Infallible;

    fn enter(&mut self) -> Result<(), Self::Error> {
        self.0.lock().unwrap().push("enter");
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Self::Error> {
        self.0.lock().unwrap().push("restore");
        Ok(())
    }
}
