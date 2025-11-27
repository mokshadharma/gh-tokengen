from __future__ import annotations
from pathlib import Path
from typing import Optional, Callable, List, Tuple, Type, TYPE_CHECKING

if TYPE_CHECKING:
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.document import Document
try:
    from prompt_toolkit.validation import Validator
except ImportError:
    class Validator: # type: ignore 
        pass

from gh_tokengen.utils import ValidationError
from gh_tokengen.interactive.ui import ValidationState, raise_validation_error_with_state
from gh_tokengen.interactive.resolver import (
    FuzzyPathResolver,
    expand_home_in_path,
    determine_base_directory_for_text,
    get_subdirectories_from_path,
    resolve_directory_segment,
    check_skip_directory_part,
    apply_matching_strategy,
    make_path_absolute_from_cwd
)

class PathCompletionValidator:
    """Validator for paths when path completion is enabled."""

    def __init__(self, state: ValidationState, validation_error_class: type, no_fuzzy: bool, cwd: Path) -> None:
        """
        Initialize the validator.

        Args:
            state: Validation state for error messages
            validation_error_class: The exception class to raise on validation failure
            no_fuzzy: Whether to use fuzzy matching
            cwd: Current working directory
        """
        self.state = state
        self.validation_error_class = validation_error_class
        self.no_fuzzy = no_fuzzy
        self.cwd = cwd

    def validate(self, text: str) -> None:
        """
        Validate path text.

        Args:
            text: The path text to validate
        """
        base_dir = determine_base_directory_for_text(text, self.cwd)
        self._dispatch_path_validation_by_structure(text, base_dir)

    def _parse_path_components(self, text: str) -> Tuple[List[str], str]:
        """Parse path into directory parts and final query segment."""
        parts = text.split('/')
        return parts[:-1], parts[-1]

    def _validate_directory_exists_or_fail(self, directory: Path) -> None:
        """Validate that directory exists, raise error if not."""
        if not directory.exists() or not directory.is_dir():
            raise_validation_error_with_state(f"directory '{directory}' does not exist", self.state, self.validation_error_class)

    def _get_path_validation_candidates_or_fail(self, directory: Path) -> List[Path]:
        """Get validation candidates (dirs and .pem files), raise if directory access fails."""
        try:
            return [p for p in directory.iterdir() if p.is_dir() or (p.is_file() and p.suffix.lower() == '.pem')]
        except PermissionError:
            raise_validation_error_with_state(f"permission denied accessing '{directory}'", self.state, self.validation_error_class)
        except Exception:
            return []

    def _validate_candidates_not_empty_or_fail(self, candidates: List[Path]) -> None:
        """Validate that candidates list is not empty."""
        if not candidates:
            raise_validation_error_with_state("no matches found", self.state, self.validation_error_class)

    def _validate_query_has_match_or_fail(self, query: str, candidates: List[Path]) -> None:
        """Validate that query matches at least one candidate."""
        matches = apply_matching_strategy(query, candidates, self.no_fuzzy)
        if not matches:
            raise_validation_error_with_state("no matches found", self.state, self.validation_error_class)

    def _validate_final_query_segment(self, final_query: str, current_dir: Path) -> None:
        """Validate final query segment."""
        self._validate_directory_exists_or_fail(current_dir)
        candidates = self._get_path_validation_candidates_or_fail(current_dir)
        self._validate_query_has_match_or_fail(final_query, candidates)

    def _validate_final_query_if_present(self, final_query: str, current_dir: Path) -> None:
        """Validate final query segment if it's not empty."""
        if final_query:
            self._validate_final_query_segment(final_query, current_dir)

    def _navigate_segment_with_validation(self, i: int, part: str, current_dir: Path) -> Path:
        """Navigate one segment with validation."""
        if check_skip_directory_part(i, part):
            return current_dir

        self._validate_directory_exists_or_fail(current_dir)
        subdirs = get_subdirectories_from_path(current_dir)
        matched = resolve_directory_segment(subdirs, part, self.no_fuzzy)

        if not matched:

            raise_validation_error_with_state(f"directory '{part}' not found", self.state, self.validation_error_class)

        return matched

    def _validate_multi_segment_path(self, text: str, base_dir: Path) -> None:
        """Validate a path containing directory separators."""
        dir_parts, final_query = self._parse_path_components(text)
        current_dir = base_dir
        for i, part in enumerate(dir_parts):
            current_dir = self._navigate_segment_with_validation(i, part, current_dir)
        self._validate_final_query_if_present(final_query, current_dir)

    def _check_if_special_home_marker(self, text: str) -> bool:
        """Check if text is a special home directory marker."""
        return text in ('~', '$HOME')

    def _validate_non_special_single_segment(self, text: str, base_dir: Path) -> None:
        """Validate single segment path that is not a special marker."""
        self._validate_directory_exists_or_fail(base_dir)
        candidates = self._get_path_validation_candidates_or_fail(base_dir)
        self._validate_candidates_not_empty_or_fail(candidates)
        self._validate_query_has_match_or_fail(text, candidates)

    def _validate_single_segment_path(self, text: str, base_dir: Path) -> None:
        """Validate a simple path with no directory separators."""
        if self._check_if_special_home_marker(text):
            return
        self._validate_non_special_single_segment(text, base_dir)

    def _dispatch_path_validation_by_structure(self, text: str, base_dir: Path) -> None:
        """Dispatch to appropriate validation based on path structure."""
        if '/' in text:
            self._validate_multi_segment_path(text, base_dir)
        else:
            self._validate_single_segment_path(text, base_dir)


def check_if_text_is_empty(text: str) -> bool:
    """Check if text is empty (validation should be skipped)."""
    return not text

def update_buffer_with_resolved_path(buf: Buffer, unexpanded_path: str) -> None:
    """Update buffer text and cursor position with resolved path."""
    buf.text = unexpanded_path
    buf.cursor_position = len(unexpanded_path)


def get_expanded_path_from_result(result: Tuple[str, str]) -> Tuple[str, str]:
    """Extract unexpanded and expanded paths from resolution result."""
    unexpanded_path, expanded_path = result
    return unexpanded_path, expanded_path


def resolve_and_update_buffer_or_use_text(buf: Buffer, text: str, path_resolver: FuzzyPathResolver) -> Tuple[str, str]:
    """Resolve fuzzy path and update buffer, or return original text."""
    result = path_resolver.resolve(text)
    if result:
        unexpanded_path, expanded_path = get_expanded_path_from_result(result)
        update_buffer_with_resolved_path(buf, unexpanded_path)
        return unexpanded_path, expanded_path
    else:
        return text, text


def select_validation_path_for_no_completion(text: str) -> str:
    """Return validation path for no_path_completion mode."""
    return text


def determine_validation_path_for_completion_mode(buf: Buffer, text: str, no_path_completion: bool, path_resolver: FuzzyPathResolver) -> str:
    """Determine validation path based on completion mode."""
    if no_path_completion:
        return select_validation_path_for_no_completion(text)
    else:
        _, validation_path = resolve_and_update_buffer_or_use_text(buf, text, path_resolver)
        return validation_path


def expand_home_variables(validation_path: str) -> str:
    """Expand $HOME variable in path string."""
    return validation_path.replace('$HOME', str(Path.home()))


def expand_tilde_in_path(path_str: str) -> Path:
    """Expand tilde in path string to Path object."""
    return Path(path_str).expanduser()

def make_absolute_if_relative(path: Path, cwd: Path) -> Path:
    """Make path absolute if it's relative."""
    if not path.is_absolute():
        return cwd / path
    else:
        return path

def set_error_and_abort(message: str, state: ValidationState) -> None:
    """Set error message in state (never returns normally)."""
    state.error_message = message

def check_path_exists_or_abort(path: Path) -> bool:
    """Check if path exists, return True if exists, False if not."""
    return path.exists()

def check_path_is_directory_or_abort(path: Path) -> bool:
    """Check if path is a directory, return True if directory, False if not."""
    return path.is_dir()

def check_path_is_pem_file(path: Path) -> bool:
    """Check if path has .pem extension."""
    return path.suffix.lower() == '.pem'

def validate_path_exists_or_abort(path: Path, state: ValidationState) -> bool:
    """Validate path exists, return False and set error if not."""
    if not check_path_exists_or_abort(path):
        set_error_and_abort("not a valid *.pem file name", state)
        return False
    return True

def validate_path_not_directory_or_abort(path: Path, state: ValidationState) -> bool:
    """Validate path is not a directory, return False and set error if it is."""
    if check_path_is_directory_or_abort(path):
        set_error_and_abort("this is a directory, not a *.pem file", state)
        return False
    return True

def validate_path_is_pem_or_abort(path: Path, state: ValidationState) -> bool:
    """Validate path is a .pem file, return False and set error if not."""
    if not check_path_is_pem_file(path):
        set_error_and_abort("not a valid *.pem file name", state)
        return False
    return True

def perform_path_validation_checks(path: Path, state: ValidationState) -> bool:
    """Perform all path validation checks, return False on any failure."""
    return (validate_path_exists_or_abort(path, state) and
           validate_path_not_directory_or_abort(path, state) and
           validate_path_is_pem_or_abort(path, state))

def validate_resolved_path_or_set_error(validation_path: str, state: ValidationState, cwd: Path) -> bool:
    """Validate resolved path through all checks, return False on failure."""
    try:
        expanded = expand_home_variables(validation_path)
        path = expand_tilde_in_path(expanded)
        absolute_path = make_absolute_if_relative(path, cwd)
        return perform_path_validation_checks(absolute_path, state)
    except Exception:
        set_error_and_abort("not a valid *.pem file name", state)
        return False

def handle_path_mode_validation(buf: Buffer, text: str, state: ValidationState, cwd: Path, no_path_completion: bool, path_resolver: FuzzyPathResolver) -> bool:
    """Handle validation for path modes, return False if validation fails."""
    if check_if_text_is_empty(text):
        return False
    validation_path = determine_validation_path_for_completion_mode(buf, text, no_path_completion, path_resolver)
    return validate_resolved_path_or_set_error(validation_path, state, cwd)

def extract_first_line_from_error(error: ValidationError) -> str:
    """Extract first line from ValidationError message."""
    return str(error).split('\n')[0]

def validate_with_custom_validator_or_set_error(text: str, validator_func: Optional[Callable[[str], None]], state: ValidationState) -> bool:
    """Validate using custom validator, return False if validation fails."""
    if validator_func:
        try:
            validator_func(text)
            return True
        except ValidationError as e:
            set_error_and_abort(extract_first_line_from_error(e), state)
            return False
    return True

def handle_non_path_mode_validation(text: str, validator_func: Optional[Callable[[str], None]], state: ValidationState) -> bool:
    """Handle validation for non-path modes, return False if validation fails."""
    return validate_with_custom_validator_or_set_error(text, validator_func, state)

def check_if_path_mode_enabled(enable_path_completion: bool, no_path_completion: bool) -> bool:
    """Check if path mode is enabled (either completion or validation only)."""
    return enable_path_completion or no_path_completion


def perform_validation_by_mode(buf: Buffer, text: str, state: ValidationState, cwd: Path, enable_path_completion: bool, no_path_completion: bool, path_resolver: FuzzyPathResolver, validator_func: Optional[Callable[[str], None]]) -> bool:
    """Perform validation based on current mode, return False if validation fails."""
    if check_if_path_mode_enabled(enable_path_completion, no_path_completion):
        return handle_path_mode_validation(buf, text, state, cwd, no_path_completion, path_resolver)
    else:
        return handle_non_path_mode_validation(text, validator_func, state)

def accept_buffer_input(buf: Buffer) -> None:
    """Accept the buffer input."""
    buf.validate_and_handle()

def validate_and_accept_if_valid(buf: Buffer, text: str, state: ValidationState, cwd: Path, enable_path_completion: bool, no_path_completion: bool, path_resolver: FuzzyPathResolver, validator_func: Optional[Callable[[str], None]]) -> None:
    """Validate input and accept if valid."""
    if perform_validation_by_mode(buf, text, state, cwd, enable_path_completion, no_path_completion, path_resolver, validator_func):
        accept_buffer_input(buf)

class EnterKeyValidator:
    """Handles validation logic when user presses Enter."""

    def __init__(
        self,
        state: ValidationState,
        enable_path_completion: bool,
        no_path_completion: bool,
        path_resolver: FuzzyPathResolver,
        validator_func: Optional[Callable[[str], None]],
        cwd: Path
    ) -> None:
        self.state = state
        self.enable_path_completion = enable_path_completion
        self.no_path_completion = no_path_completion
        self.path_resolver = path_resolver
        self.validator_func = validator_func
        self.cwd = cwd

    def validate_and_accept(self, buf: Buffer, text: str) -> None:
        """Validate input and accept if valid."""
        validate_and_accept_if_valid(
            buf,
            text,
            self.state,
            self.cwd,
            self.enable_path_completion,
            self.no_path_completion,
            self.path_resolver,
            self.validator_func
        )

class NoPathCompletionValidator:
    """Validator for paths when path completion is disabled."""

    def __init__(self, state: ValidationState, validation_error_class: type) -> None:
        """
        Initialize the validator.

        Args:
            state: Validation state for error messages
            validation_error_class: The exception class to raise on validation failure
        """
        self.state = state
        self.validation_error_class = validation_error_class

    def validate_path_exists_or_fail(self, path: Path) -> None:
        """Validate that path exists, raise error if not."""
        if not path.exists():
            raise_validation_error_with_state("file does not exist", self.state, self.validation_error_class)

    def validate_path_is_file_or_fail(self, path: Path) -> None:
        """Validate that path is a regular file, raise error if not."""
        if not path.is_file():
            raise_validation_error_with_state("not a regular file", self.state, self.validation_error_class)

    def validate_path_is_readable_or_fail(self, path: Path) -> None:
        """Validate that path is readable, raise error if not."""
        try:
            with open(path, 'r'):
                pass
        except (PermissionError, OSError):
            raise_validation_error_with_state("file is not readable", self.state, self.validation_error_class)

    def validate(self, expanded_path: Path, cwd: Path) -> None:
        """
        Perform validation on the expanded path.

        Args:
            expanded_path: The path with ~ and env vars expanded
            cwd: Current working directory for resolving relative paths
        """
        absolute_path = make_path_absolute_from_cwd(expanded_path, cwd)
        self.validate_path_exists_or_fail(absolute_path)
        self.validate_path_is_file_or_fail(absolute_path)
        self.validate_path_is_readable_or_fail(absolute_path)

class PromptInputValidator(Validator):
    """Validator for prompt input based on current mode."""

    def __init__(
        self,
        state: ValidationState,
        enable_path_completion: bool,
        no_path_completion: bool,
        no_fuzzy: bool,
        path_completion_validator: PathCompletionValidator,
        no_path_completion_validator: NoPathCompletionValidator,
        validation_error_class: Type[BaseException],
        cwd: Path
    ) -> None:
        self.state = state
        self.enable_path_completion = enable_path_completion
        self.no_path_completion = no_path_completion
        self.no_fuzzy = no_fuzzy
        self.path_completion_validator = path_completion_validator
        self.no_path_completion_validator = no_path_completion_validator
        self.validation_error_class = validation_error_class
        self.cwd = cwd

    def _clear_error_state(self) -> None:
        """Clear error message at the start of validation."""
        self.state.error_message = ""

    def _dispatch_validation_by_completion_mode(self, expanded_path: Path, text: str) -> None:
        """Dispatch to appropriate validation handler based on completion mode."""
        if self.no_path_completion:
            self.no_path_completion_validator.validate(expanded_path, self.cwd)
        else:
            self.path_completion_validator.validate(text)

    def _execute_path_validation_with_exception_handling(self, text: str) -> None:
        """Execute path validation with proper exception handling."""
        try:
            expanded_path = expand_home_in_path(text)
            self._dispatch_validation_by_completion_mode(expanded_path, text)
        except self.validation_error_class:
            raise
        except Exception:
            pass

    def _check_if_path_validation_enabled(self) -> bool:
        """Check if path validation is enabled in current mode."""
        return check_if_path_mode_enabled(self.enable_path_completion, self.no_path_completion)

    def _dispatch_validation_by_mode(self, text: str) -> None:
        """Dispatch validation based on whether path validation is enabled."""
        if self._check_if_path_validation_enabled():
            self._execute_path_validation_with_exception_handling(text)

    def _execute_validation_workflow(self, text: str) -> None:
        """Execute the complete validation workflow based on mode."""
        self._dispatch_validation_by_mode(text)

    def _handle_empty_text_or_validate(self, text: str) -> None:
        """Handle empty text case or proceed with validation."""
        if check_if_text_is_empty(text):
            return
        self._execute_validation_workflow(text)

    def validate(self, document: Document) -> None:
        """Validate input according to current mode and configuration."""
        text = document.text.strip()
        self._clear_error_state()
        self._handle_empty_text_or_validate(text)
