import sys
from pathlib import Path
from typing import Optional, Callable
from gh_tokengen.interactive.completer import normalize_completion_flags, create_completer_for_path_mode
from gh_tokengen.interactive.ui import create_validation_state, create_bottom_toolbar_func, ErrorFlashController
from gh_tokengen.interactive.validators import NoPathCompletionValidator, PathCompletionValidator, PromptInputValidator, EnterKeyValidator
from gh_tokengen.interactive.resolver import FuzzyPathResolver
from gh_tokengen.interactive.session import PromptSessionFactory, prompt_with_session, handle_import_error_with_fallback, handle_interrupt_error, import_prompt_toolkit_modules, KeyBindingHandlers

def prompt_for_input(
    prompt_text: str,
    enable_path_completion: bool = False,
    validator_func: Optional[Callable[[str], None]] = None,
    no_fuzzy: bool = False,
    no_path_completion: bool = False
) -> str:
    """
    Prompt user for input on stderr with rich line editing.

    Args:
        prompt_text: The prompt to display
        enable_path_completion: Enable file path autocompletion with fuzzy matching
        validator_func: Optional validation function for non-path inputs
        no_fuzzy: Use prefix-only matching instead of fuzzy matching
        no_path_completion: Disable path completion entirely and only validate

    Returns:
        User input string
    """
    no_fuzzy, enable_path_completion = normalize_completion_flags(no_path_completion, no_fuzzy, enable_path_completion)
    try:
        modules = import_prompt_toolkit_modules()
        PromptSession = modules['PromptSession']
        EditingMode = modules['EditingMode']
        create_output = modules['create_output']
        PTValidationError = modules['PTValidationError']
        HTML = modules['HTML']
        KeyBindings = modules['KeyBindings']
        Keys = modules['Keys']
        SelectionType = modules['SelectionType']

        SelectionState = modules['SelectionState']
        completer = create_completer_for_path_mode(enable_path_completion, no_fuzzy)
        output = create_output(stdout=sys.stderr)

        state = create_validation_state()

        bottom_toolbar = create_bottom_toolbar_func(state, HTML)

        no_path_completion_validator = NoPathCompletionValidator(state, PTValidationError)
        path_completion_validator = PathCompletionValidator(state, PTValidationError, no_fuzzy, Path.cwd())
        path_resolver = FuzzyPathResolver(Path.cwd(), no_fuzzy, enable_path_completion)

        validator = PromptInputValidator(
            state,
            enable_path_completion,
            no_path_completion,
            no_fuzzy,
            path_completion_validator,
            no_path_completion_validator,
            PTValidationError,
            Path.cwd()
        )

        # Custom key bindings
        enter_key_validator = EnterKeyValidator(
            state,
            enable_path_completion,
            no_path_completion,
            path_resolver,
            validator_func,
            Path.cwd()
        )

        flash_controller = ErrorFlashController(state, enable_path_completion)

        key_binding_handlers = KeyBindingHandlers(
            state,
            enable_path_completion,
            enter_key_validator,
            flash_controller,
            KeyBindings,
            Keys,
            SelectionType,
            SelectionState,
                completer,
        )
        kb = key_binding_handlers.create_key_bindings()
        session_factory = PromptSessionFactory(
            prompt_text,
            enable_path_completion,
            no_path_completion,
            validator_func,
            state,
            PromptSession,
            EditingMode,
            completer,
            output,
            validator,
            kb,
            bottom_toolbar
        )
        session = session_factory.create_session()
        return prompt_with_session(session)

    except ImportError as e:
        return handle_import_error_with_fallback(e, prompt_text)
    except (EOFError, KeyboardInterrupt):
        handle_interrupt_error()


