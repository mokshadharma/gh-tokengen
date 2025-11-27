import threading
import time
from typing import Optional, Callable, Any, NoReturn

def create_toolbar_display(flash_error: bool, error_message: str, HTML: Any) -> Any:
    """Create toolbar display based on error state."""
    if flash_error:
        return HTML('<style bg="ansired" fg="ansiblack">  {}  </style>').format(error_message)
    elif error_message:
        return HTML('<style fg="ansired">  {}  </style>').format(error_message)
    return ""
class ValidationState:
    """State container for validation UI feedback."""

    def __init__(self) -> None:
        self.error_message: str = ""
        self.flash_error: bool = False
        self.flash_thread: Optional[threading.Thread] = None
        self.yank_buffer: str = ""


def create_validation_state() -> ValidationState:
    """Create a new ValidationState instance."""
    return ValidationState()


def create_bottom_toolbar_func(state: ValidationState, HTML: Any) -> Callable[[], Any]:
    """
    Create bottom toolbar function that captures state.

    Args:
        state: The validation state object
        HTML: The prompt_toolkit HTML class

    Returns:
        A function that returns the toolbar content
    """
    def bottom_toolbar() -> Any:
        return create_toolbar_display(state.flash_error, state.error_message, HTML)
    return bottom_toolbar


def raise_validation_error_with_state(message: str, state: ValidationState, validation_error_class: type) -> NoReturn:
    """Set error state and raise validation error (never returns)."""
    state.error_message = message
    raise validation_error_class(message=message)
class ErrorFlashController:
    """Controls error flash animation in the toolbar."""

    def __init__(self, state: ValidationState, enable_path_completion: bool) -> None:
        """
        Initialize the controller.

        Args:
            state: Validation state for flash state
            enable_path_completion: Whether path completion is enabled
        """
        self.state = state
        self.enable_path_completion = enable_path_completion

    def should_flash(self, buf: Any) -> bool:
        """Check if error should be flashed."""
        return bool(self.enable_path_completion and self.state.error_message and not buf.complete_state)

    def _enable_flash_error_state(self) -> None:
        """Enable flash error state."""
        self.state.flash_error = True

    def _create_unflash_callback(self, event: Any) -> Callable[[], None]:
        """Create callback to unflash error after delay."""
        def unflash() -> None:
            time.sleep(0.5)
            self.state.flash_error = False
            event.app.invalidate()
        return unflash

    def _check_if_flash_thread_is_inactive(self) -> bool:
        """Check if flash thread is None or not alive."""
        return self.state.flash_thread is None or not self.state.flash_thread.is_alive()

    def _start_unflash_thread(self, unflash_callback: Callable[[], None]) -> None:
        """Start unflash thread with callback."""
        self.state.flash_thread = threading.Thread(target=unflash_callback, daemon=True)
        if self.state.flash_thread:
            self.state.flash_thread.start()

    def _start_unflash_thread_if_inactive(self, event: Any) -> None:
        """Start unflash thread if no active thread exists."""
        if self._check_if_flash_thread_is_inactive():
            unflash_callback = self._create_unflash_callback(event)
            self._start_unflash_thread(unflash_callback)

    def flash(self, event: Any) -> None:
        """Perform error flash animation."""
        self._enable_flash_error_state()
        self._start_unflash_thread_if_inactive(event)

    def _perform_normal_tab_completion(self, buf: Any) -> None:
        """Perform normal tab completion."""
        buf.complete_next()

    def handle_tab(self, buf: Any, event: Any) -> None:
        """Handle tab key based on current state."""
        if self.should_flash(buf):
            self.flash(event)
        else:
            self._perform_normal_tab_completion(buf)

