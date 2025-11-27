from __future__ import annotations
import threading
import time
from typing import Optional, Callable, Dict, Any, NoReturn, TYPE_CHECKING, cast
from gh_tokengen.utils import eprint, fatal_error
from gh_tokengen.interactive.ui import ValidationState, ErrorFlashController
from gh_tokengen.interactive.validators import EnterKeyValidator
from gh_tokengen.interactive.completer import detect_editing_mode_from_inputrc, select_editing_mode_by_string
from prompt_toolkit.completion import CompleteEvent
from gh_tokengen.interactive.completer import FuzzyPemCompleter

if TYPE_CHECKING:
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.key_binding import KeyPressEvent
    from prompt_toolkit.shortcuts import PromptSession
    from prompt_toolkit.completion import Completer
    from prompt_toolkit.validation import Validator
    from prompt_toolkit.output import Output
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.enums import EditingMode
    from prompt_toolkit.keys import Keys
    from prompt_toolkit.selection import SelectionType, SelectionState


def select_validator_for_mode(enable_path_completion: bool, validator: Validator) -> Optional[Validator]:
    """Select validator based on path completion mode."""
    if enable_path_completion:
        return validator
    else:
        return None


def select_toolbar_for_modes(enable_path_completion: bool, no_path_completion: bool, validator_func: Optional[Callable[[str], None]], bottom_toolbar: Callable[[], HTML]) -> Optional[Callable[[], HTML]]:
    """Select toolbar function based on validation modes."""
    if enable_path_completion or no_path_completion or validator_func:
        return bottom_toolbar
    else:
        return None


def attach_no_path_completion_handler(session: PromptSession[str], state: ValidationState) -> None:
    """Attach text change handler for no_path_completion mode."""
    def on_text_changed(_: Buffer) -> None:
        state.error_message = ""
    session.default_buffer.on_text_changed += on_text_changed


def attach_auto_expansion_handler(session: PromptSession[str], completer: Completer) -> None:
    """Attach auto-expansion handler for path completion."""
    def on_text_changed(_: Buffer) -> None:
        buf = session.default_buffer
        text = buf.text
        if buf.complete_state:
            return
        if text and not text.endswith('/') and '/' not in text[:-1] and text not in ('~', '$HOME'):
            try:
                completions = list(completer.get_completions(buf.document, CompleteEvent(text_inserted=False, completion_requested=True)))
                if len(completions) == 1:
                    completion = completions[0]
                    if completion.text.endswith('/'):
                        buf.text = completion.text
                        buf.cursor_position = len(completion.text)
            except Exception:
                pass
    session.default_buffer.on_text_changed += on_text_changed


def attach_text_handlers_for_modes(session: PromptSession[str], no_path_completion: bool, enable_path_completion: bool, completer: Optional[Completer], state: ValidationState) -> None:
    """Attach appropriate text change handlers based on modes."""
    if no_path_completion:
        attach_no_path_completion_handler(session, state)
    if enable_path_completion and completer:
        attach_auto_expansion_handler(session, completer)


def prompt_with_session(session: PromptSession[str]) -> str:
    """Prompt user with session and return stripped result."""
    result = session.prompt()
    return result.strip()


def handle_import_error_with_fallback(e: Exception, prompt_text: str) -> str:
    """Handle ImportError by falling back to basic input."""
    eprint(f"Warning: Advanced input features unavailable ({e})")
    eprint(prompt_text, end='')
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        eprint()
        fatal_error("Input cancelled by user")


def handle_interrupt_error() -> NoReturn:
    """Handle keyboard interrupt by showing message and exiting."""
    eprint()
    fatal_error("Input cancelled by user")


def import_prompt_toolkit_modules() -> Dict[str, Any]:
    """
    Import prompt_toolkit modules and return them in a dictionary.

    Returns:
        Dictionary containing imported modules and classes.

    Raises:
        ImportError: If prompt_toolkit or dependencies are not available.
    """
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.enums import EditingMode
        from prompt_toolkit.output import create_output
        from prompt_toolkit.validation import Validator, ValidationError as PTValidationError
        from prompt_toolkit.formatted_text import HTML
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.keys import Keys
        from prompt_toolkit.selection import SelectionType
        from prompt_toolkit.selection import SelectionState

        return {
            'PromptSession': PromptSession,
            'EditingMode': EditingMode,
            'create_output': create_output,
            'Validator': Validator,
            'PTValidationError': PTValidationError,
            'HTML': HTML,
            'KeyBindings': KeyBindings,
            'Keys': Keys,
                'SelectionType': SelectionType,
                'SelectionState': SelectionState,
        }
    except ImportError as e:
        raise ImportError(f"Required prompt_toolkit modules not found: {e}")


class KeyBindingHandlers:
    """Handles key bindings for the prompt."""

    def __init__(
        self,
        state: ValidationState,
        enable_path_completion: bool,
        enter_key_validator: EnterKeyValidator,
        flash_controller: ErrorFlashController,
        KeyBindings: type[KeyBindings],
        Keys: type[Keys],
            SelectionType: type[SelectionType],
            SelectionState: type[SelectionState],
            completer: Optional[Completer] = None,
    ) -> None:
        self.state = state
        self.enable_path_completion = enable_path_completion
        self.enter_key_validator = enter_key_validator
        self.flash_controller = flash_controller
        self.completer = completer
        self.KeyBindings = KeyBindings
        self.Keys = Keys
        self.SelectionState = SelectionState
        self.SelectionType = SelectionType

    def create_key_bindings(self) -> KeyBindings:
        """Create and return configured key bindings."""
        kb = self.KeyBindings()

        @kb.add(self.Keys.Backspace)
        def handle_backspace(event: KeyPressEvent) -> None:
            """Handle backspace - keep completions visible."""
            buf = event.app.current_buffer
            if buf.cursor_position > 0:
                buf.delete_before_cursor(count=1)
                # Trigger completions if path completion is enabled
                if self.enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        @kb.add(self.Keys.ControlW)
        def handle_ctrl_w(event: KeyPressEvent) -> None:
            """Handle Ctrl-W (delete word) - keep completions visible and save to yank buffer."""
            buf = event.app.current_buffer
            # Delete word before cursor (standard behavior)
            if buf.text:
                pos = buf.cursor_position
                # Find start of word
                text_before = buf.text[:pos]

                # Skip trailing whitespace
                while text_before and text_before[-1] in ' \t':
                    text_before = text_before[:-1]
                # Delete trailing slash if present
                if text_before and text_before[-1] == '/':
                    text_before = text_before[:-1]
                # Delete word characters
                while text_before and text_before[-1] not in ' \t/':
                    text_before = text_before[:-1]

                new_pos = len(text_before)

                # Save deleted text to yank buffer
                deleted_text = buf.text[new_pos:pos]
                if deleted_text:
                    self.state.yank_buffer = deleted_text

                buf.cursor_position = new_pos
                buf.text = text_before + buf.text[pos:]

                # Trigger completions if path completion is enabled
                if self.enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        @kb.add(self.Keys.ControlU)
        def handle_ctrl_u(event: KeyPressEvent) -> None:
            """Handle Ctrl-U (delete from beginning of line to cursor) - save to yank buffer."""
            buf = event.app.current_buffer
            if buf.cursor_position > 0:
                # Save deleted text to yank buffer
                deleted_text = buf.text[:buf.cursor_position]
                if deleted_text:
                    self.state.yank_buffer = deleted_text

                # Delete from start to cursor
                buf.text = buf.text[buf.cursor_position:]
                buf.cursor_position = 0

                # Trigger completions if path completion is enabled
                if self.enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        @kb.add(self.Keys.ControlY)
        def handle_ctrl_y(event: KeyPressEvent) -> None:
            """Handle Ctrl-Y (yank/paste) - paste back last deleted text."""
            buf = event.app.current_buffer
            if self.state.yank_buffer:
                # Insert yanked text at cursor position
                pos = buf.cursor_position
                buf.text = buf.text[:pos] + self.state.yank_buffer + buf.text[pos:]
                buf.cursor_position = pos + len(self.state.yank_buffer)

                # Trigger completions if path completion is enabled
                if self.enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        @kb.add('/')
        def handle_slash(event: KeyPressEvent) -> None:
            """Handle forward slash - prevent double slashes."""
            buf = event.app.current_buffer
            if buf.cursor_position > 0 and buf.text[buf.cursor_position - 1] == '/':
                # Flash the slash by selecting it briefly without moving cursor
                # This preserves the completion menu state
                buf.selection_state = self.SelectionState(
                    original_cursor_position=buf.cursor_position - 1,
                    type=self.SelectionType.CHARACTERS
                )
                
                def unflash() -> None:
                    time.sleep(0.1)
                    buf.selection_state = None
                    event.app.invalidate()

                t = threading.Thread(target=unflash, daemon=True)
                t.start()
            else:
                buf.insert_text('/')
                # Auto-expand if unique directory
                if self.enable_path_completion and self.completer and isinstance(self.completer, FuzzyPemCompleter):
                    expanded = self.completer.expand_path_if_unique(buf.text)
                    if expanded:
                        buf.text = expanded
                        buf.cursor_position = len(expanded)

                # Trigger completions if path completion is enabled
                if self.enable_path_completion and not buf.complete_state:
                    buf.start_completion(select_first=False)

        @kb.add(self.Keys.ControlM)  # Enter key
        def handle_enter(event: KeyPressEvent) -> None:
            """Handle Enter key - validate before accepting."""
            buf = event.app.current_buffer
            text = buf.text.strip()
            self.enter_key_validator.validate_and_accept(buf, text)

        @kb.add(self.Keys.ControlI)  # Tab key
        def handle_tab(event: KeyPressEvent) -> None:
            """Handle Tab key - show completions or flash error."""
            buf = event.app.current_buffer
            self.flash_controller.handle_tab(buf, event)

        return kb

def check_if_path_mode_enabled(enable_path_completion: bool, no_path_completion: bool) -> bool:
    """Check if path mode is enabled (either completion or validation only)."""
    return enable_path_completion or no_path_completion

class PromptSessionFactory:
    """Factory for creating configured PromptSession instances."""

    def __init__(
        self,
        prompt_text: str,
        enable_path_completion: bool,
        no_path_completion: bool,
        validator_func: Optional[Callable[[str], None]],
        state: ValidationState,
        PromptSession: type[PromptSession[str]],
        EditingMode: type[EditingMode],
        completer: Optional[Completer],
        output: Output,
        validator: Validator,
        key_bindings: KeyBindings,
        bottom_toolbar: Callable[[], HTML]
    ) -> None:
        self.prompt_text = prompt_text
        self.enable_path_completion = enable_path_completion
        self.no_path_completion = no_path_completion
        self.validator_func = validator_func
        self.state = state
        self.PromptSession = PromptSession
        self.EditingMode = EditingMode
        self.completer = completer
        self.output = output
        self.validator = validator
        self.key_bindings = key_bindings
        self.bottom_toolbar = bottom_toolbar

    def create_session(self) -> PromptSession[str]:
        """Create and return a configured PromptSession."""
        mode_str = detect_editing_mode_from_inputrc()
        editing_mode = select_editing_mode_by_string(mode_str, self.EditingMode)

        selected_validator = select_validator_for_mode(self.enable_path_completion, self.validator)
        selected_toolbar = select_toolbar_for_modes(self.enable_path_completion, self.no_path_completion, self.validator_func, self.bottom_toolbar)

        session = self.PromptSession(
            message=self.prompt_text,
            editing_mode=editing_mode,
            completer=self.completer,
            complete_while_typing=self.enable_path_completion,
            output=self.output,
            enable_history_search=False,
            validator=selected_validator,
            validate_while_typing=self.enable_path_completion,
            key_bindings=self.key_bindings,
            bottom_toolbar=selected_toolbar,
            reserve_space_for_menu=8
        )

        attach_text_handlers_for_modes(session, self.no_path_completion, self.enable_path_completion, self.completer, self.state)
        return session
