import re
from pathlib import Path
from typing import List, Tuple, Union, Optional, Any, Iterator, Dict
from gh_tokengen.utils import natural_sort_key

class FuzzyPemCompleter:
    """
    Custom completer for PEM file selection with fuzzy matching.

    Supports directory navigation with fuzzy matching on each path component.
    Matches *.pem files and directories, with context-aware searching.

    Implements prompt_toolkit's Completer protocol via duck typing.
    """

    def __init__(self, base_dir: Path, no_fuzzy: bool = False) -> None:
        """
        Initialize the fuzzy completer.

        Args:
            base_dir: Starting directory for path completion
            no_fuzzy: If True, use prefix-only matching instead of fuzzy matching
        """
        self.base_dir: Path = base_dir
        self.no_fuzzy: bool = no_fuzzy
        from rapidfuzz import fuzz, process
        self.fuzz: Any = fuzz
        self.process: Any = process
        # Sentinel values for flow control without exposing conditionals
        self._EMPTY_RESULT: List[Tuple[str, float, Path]] = []
        self._NO_EARLY_EXIT = object()

    def _expand_path(self, path_str: str) -> Path:
        """Expand ~ and $HOME in path string."""
        expanded: str = path_str.replace('$HOME', str(Path.home()))
        return Path(expanded).expanduser()

    def _get_candidates(self, directory: Path, is_final_segment: bool) -> List[Path]:
        """
        Get completion candidates from a directory.

        Args:
            directory: Directory to search in
            is_final_segment: If True, include *.pem files; if False, only directories

        Returns:
            List of Path objects for candidates
        """
        if not directory.exists() or not directory.is_dir():
            return []

        candidates: List[Path] = []
        try:
            for item in directory.iterdir():
                if item.is_dir():
                    candidates.append(item)
                elif is_final_segment and item.is_file() and item.suffix.lower() == '.pem':
                    candidates.append(item)
        except PermissionError:
            pass

        return candidates

    def _check_query_empty(self, query: str) -> bool:
        """Check if query is empty."""
        return not query

    def _handle_empty_query_or_continue(self, query: str) -> Union[List[Tuple[str, float, Path]], Any]:
        """Return empty list for empty query, sentinel to continue otherwise."""
        return self._EMPTY_RESULT if self._check_query_empty(query) else self._NO_EARLY_EXIT

    def _check_query_has_uppercase(self, query: str) -> bool:
        """Check if query contains any uppercase characters."""
        return any(c.isupper() for c in query)

    def _find_case_sensitive_prefix_matches(self, query: str, candidates: List[Path]) -> List[Path]:
        """Find candidates with case-sensitive prefix match."""
        return [c for c in candidates if c.name.startswith(query)]

    def _find_case_insensitive_prefix_matches(self, query: str, candidates: List[Path]) -> List[Path]:
        """Find candidates with case-insensitive prefix match."""
        query_lower: str = query.lower()
        return [c for c in candidates if c.name.lower().startswith(query_lower)]

    def _select_prefix_match_strategy(self, query: str, candidates: List[Path]) -> List[Path]:
        """Select and apply appropriate prefix matching strategy based on query case."""
        query_has_upper: bool = self._check_query_has_uppercase(query)
        return (self._find_case_sensitive_prefix_matches(query, candidates)
                if query_has_upper
                else self._find_case_insensitive_prefix_matches(query, candidates))

    def _check_matches_empty(self, matches: List[Path]) -> bool:
        """Check if matches list is empty."""
        return not matches

    def _handle_no_matches_or_continue(self, matches: List[Path]) -> Union[List[Tuple[str, float, Path]], Any]:
        """Return empty list if no matches, sentinel to continue otherwise."""
        return self._EMPTY_RESULT if self._check_matches_empty(matches) else self._NO_EARLY_EXIT

    def _score_prefix_matches(self, matches: List[Path]) -> List[Tuple[str, float, Path]]:
        """Assign uniform score to all prefix matches."""
        return [(c.name, 100.0, c) for c in matches]

    def _perform_prefix_matching_workflow(self, matches: List[Path]) -> List[Tuple[str, float, Path]]:
        """Execute prefix matching workflow: check for no matches then score."""
        no_matches_result = self._handle_no_matches_or_continue(matches)
        return no_matches_result if no_matches_result is not self._NO_EARLY_EXIT else self._score_prefix_matches(matches)

    def _perform_prefix_matching(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Complete prefix matching workflow with internal decision-making."""
        matches = self._select_prefix_match_strategy(query, candidates)
        return self._perform_prefix_matching_workflow(matches)

    def _check_ordered_characters(self, query_str: str, target_str: str) -> bool:
        """Check if all characters in query appear in order in target."""
        query_lower: str = query_str.lower()
        target_lower: str = target_str.lower()
        query_idx: int = 0
        for char in target_lower:
            if query_idx < len(query_lower) and char == query_lower[query_idx]:
                query_idx += 1
        return query_idx == len(query_lower)

    def _filter_by_ordered_characters(self, query: str, candidates: List[Path]) -> List[Path]:
        """Filter candidates to only those with query characters in order."""
        return [c for c in candidates if self._check_ordered_characters(query, c.name)]

    def _extract_names_from_candidates(self, candidates: List[Path]) -> List[str]:
        """Extract name strings from candidate paths."""
        return [c.name for c in candidates]

    def _perform_fuzzy_scoring(self, query: str, names: List[str]) -> List[Tuple[str, float, int]]:
        """Score candidates using fuzzy matching algorithm."""
        return self.process.extract(query, names, scorer=self.fuzz.QRatio, limit=None)

    def _create_name_to_path_lookup(self, candidates: List[Path]) -> Dict[str, Path]:
        """Create dictionary mapping candidate names to paths."""
        return {c.name: c for c in candidates}

    def _check_has_prefix_match(self, name: str, query: str) -> bool:
        """Check if name starts with query (case-insensitive)."""
        return name.lower().startswith(query.lower())

    def _calculate_adjusted_score(self, name: str, query: str, base_score: float) -> float:
        """Calculate score with prefix bonus applied internally."""
        return base_score + 50.0 if self._check_has_prefix_match(name, query) else base_score

    def _apply_prefix_bonus_to_match(self, name: str, score: float, query: str, lookup: Dict[str, Path]) -> Tuple[str, float, Path]:
        """Apply prefix bonus to a single match and return result tuple."""
        path: Path = lookup[name]
        adjusted_score: float = self._calculate_adjusted_score(name, query, score)
        return (name, adjusted_score, path)

    def _apply_prefix_bonuses(self, matches: List[Tuple[str, float, int]], query: str, lookup: Dict[str, Path]) -> List[Tuple[str, float, Path]]:
        """Apply prefix bonus to all matches and return adjusted results."""
        return [self._apply_prefix_bonus_to_match(name, score, query, lookup) for name, score, _ in matches]

    def _continue_with_fuzzy_scoring(self, valid_candidates: List[Path], query: str) -> List[Tuple[str, float, Path]]:
        """Continue with fuzzy scoring after validation."""
        names: List[str] = self._extract_names_from_candidates(valid_candidates)
        matches: List[Tuple[str, float, int]] = self._perform_fuzzy_scoring(query, names)
        lookup: Dict[str, Path] = self._create_name_to_path_lookup(valid_candidates)
        return self._apply_prefix_bonuses(matches, query, lookup)

    def _perform_fuzzy_matching_workflow(self, valid_candidates: List[Path], query: str) -> List[Tuple[str, float, Path]]:
        """Execute fuzzy matching workflow: check for no matches then score."""
        no_matches_result = self._handle_no_matches_or_continue(valid_candidates)
        return no_matches_result if no_matches_result is not self._NO_EARLY_EXIT else self._continue_with_fuzzy_scoring(valid_candidates, query)

    def _perform_fuzzy_matching(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Complete fuzzy matching workflow with internal decision-making."""
        valid_candidates = self._filter_by_ordered_characters(query, candidates)
        return self._perform_fuzzy_matching_workflow(valid_candidates, query)

    def _select_matching_strategy(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Dispatch to appropriate matching strategy (prefix or fuzzy) based on mode."""
        return (self._perform_prefix_matching(query, candidates)
                if self.no_fuzzy
                else self._perform_fuzzy_matching(query, candidates))

    def _check_is_pem_file(self, path: Path) -> bool:
        """Check if path is a PEM file."""
        return path.is_file() and path.suffix.lower() == '.pem'

    def _separate_pem_files(self, results: List[Tuple[str, float, Path]]) -> Tuple[List[Tuple[str, float, Path]], List[Tuple[str, float, Path]]]:
        """Separate results into PEM files and other matches."""
        pem_results: List[Tuple[str, float, Path]] = [(name, score, path) for name, score, path in results if self._check_is_pem_file(path)]
        other_results: List[Tuple[str, float, Path]] = [(name, score, path) for name, score, path in results if not self._check_is_pem_file(path)]
        return pem_results, other_results

    def _sort_by_score_and_name(self, results: List[Tuple[str, float, Path]]) -> None:
        """Sort results by score (descending) then natural sort (in-place)."""
        results.sort(key=lambda x: (-x[1], natural_sort_key(x[0])))

    def _organize_and_sort_results(self, results: List[Tuple[str, float, Path]]) -> List[Tuple[str, float, Path]]:
        """Separate PEM files, sort each group, and combine with PEM files first."""
        pem_results: List[Tuple[str, float, Path]]
        other_results: List[Tuple[str, float, Path]]
        pem_results, other_results = self._separate_pem_files(results)
        self._sort_by_score_and_name(pem_results)
        self._sort_by_score_and_name(other_results)
        return pem_results + other_results

    def _continue_with_matching(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Continue with matching strategy selection and result organization."""
        matching_results: List[Tuple[str, float, Path]] = self._select_matching_strategy(query, candidates)
        return self._organize_and_sort_results(matching_results)

    def _dispatch_to_matching_or_return_early(self, empty_query_result: Union[List[Tuple[str, float, Path]], Any], query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """Dispatch to matching workflow or return early exit result (decision made internally)."""
        return empty_query_result if empty_query_result is not self._NO_EARLY_EXIT else self._continue_with_matching(query, candidates)

    def _fuzzy_match(self, query: str, candidates: List[Path]) -> List[Tuple[str, float, Path]]:
        """
        Perform fuzzy matching on candidates.

        Args:
            query: Search query string
            candidates: List of Path objects to match against

        Returns:
            List of tuples (name, score, path) with PEM files first (sorted by score then natural sort),
            then other matches (sorted by score then natural sort)
        """
        empty_query_result = self._handle_empty_query_or_continue(query)
        return self._dispatch_to_matching_or_return_early(empty_query_result, query, candidates)

    def _determine_initial_directory(self, text: str) -> Path:
        """Determine initial directory based on text prefix (handles all path prefix logic internally)."""
        if text.startswith('/'):
            return Path('/')
        elif text.startswith('~/') or text.startswith('$HOME/'):
            return Path.home()
        else:
            return self.base_dir

    def _should_skip_directory_part(self, index: int, part: str) -> bool:
        """Determine if a directory part should be skipped during navigation."""
        if not part:
            return True
        if index == 0 and part in ('~', '$HOME'):
            return True
        return False

    def _navigate_one_directory_part(self, current_dir: Path, part: str) -> Optional[Path]:
        """Navigate through one directory part, returning new directory or None if navigation fails."""
        subdirs: List[Path] = [p for p in self._get_candidates(current_dir, False)]
        if not subdirs:
            return None

        matches: List[Tuple[str, float, Path]] = self._fuzzy_match(part, subdirs)
        if matches:
            return matches[0][2]
        else:
            return None

    def _navigate_directory_parts_with_early_exit(self, dir_parts: List[str], initial_dir: Path) -> Optional[Path]:
        """Navigate through directory parts, returns None if navigation should abort early."""
        current_dir: Path = initial_dir

        for i, part in enumerate(dir_parts):
            if self._should_skip_directory_part(i, part):
                continue

            if not part:
                return None

            new_dir: Optional[Path] = self._navigate_one_directory_part(current_dir, part)
            if new_dir is None:
                return None

            current_dir = new_dir

        return current_dir

    def _separate_pem_and_directories(self, candidates: List[Path]) -> Tuple[List[Path], List[Path]]:
        """Separate candidates into PEM files and directories."""
        pem_files: List[Path] = [c for c in candidates if c.is_file() and c.suffix.lower() == '.pem']
        directories: List[Path] = [c for c in candidates if c.is_dir()]
        return pem_files, directories

    def _sort_by_natural_order(self, paths: List[Path]) -> None:
        """Sort paths list in-place by natural sort order."""
        paths.sort(key=lambda p: natural_sort_key(p.name))

    def _create_completion_for_path(self, path: Path, start_position: int, Completion: Any) -> Any:
        """Create a Completion object for a path (handles directory vs file logic internally)."""
        completion_text: str
        if path.is_dir():
            completion_text = path.name + '/'
        else:
            completion_text = path.name

        return Completion(
            completion_text,
            start_position=start_position,
            display=completion_text
        )

    def _yield_completions_for_paths(self, paths: List[Path], start_position: int, Completion: Any) -> Iterator[Any]:
        """Yield completions for a list of paths."""
        for path in paths:
            yield self._create_completion_for_path(path, start_position, Completion)

    def _yield_empty_query_completions(self, candidates: List[Path], Completion: Any) -> Iterator[Any]:
        """Handle completions when query is empty (path ends with /)."""
        pem_files, directories = self._separate_pem_and_directories(candidates)
        self._sort_by_natural_order(pem_files)
        self._sort_by_natural_order(directories)

        yield from self._yield_completions_for_paths(pem_files, 0, Completion)
        yield from self._yield_completions_for_paths(directories, 0, Completion)

    def _yield_fuzzy_query_completions(self, final_query: str, candidates: List[Path], Completion: Any) -> Iterator[Any]:
        """Handle completions when query is non-empty (fuzzy matching)."""
        fuzzy_matches: List[Tuple[str, float, Path]] = self._fuzzy_match(final_query, candidates)

        for name, score, path in fuzzy_matches:
            yield self._create_completion_for_path(path, -len(final_query), Completion)

    def _dispatch_query_completions(self, final_query: str, candidates: List[Path], Completion: Any) -> Iterator[Any]:
        """Dispatch to appropriate completion strategy based on query emptiness."""
        if not final_query:
            yield from self._yield_empty_query_completions(candidates, Completion)
        else:
            yield from self._yield_fuzzy_query_completions(final_query, candidates, Completion)

    def _handle_slash_path_completions(self, text: str, Completion: Any) -> Iterator[Any]:
        """Handle completions for paths containing slashes."""
        parts: List[str] = text.split('/')
        final_query: str = parts[-1]
        dir_parts: List[str] = parts[:-1]

        initial_dir: Path = self._determine_initial_directory(text)
        current_dir: Optional[Path] = self._navigate_directory_parts_with_early_exit(dir_parts, initial_dir)

        if current_dir is None:
            return

        candidates: List[Path] = self._get_candidates(current_dir, True)
        yield from self._dispatch_query_completions(final_query, candidates, Completion)

    def _should_block_tilde_completion(self, text: str) -> bool:
        """Determine if tilde text should block completions."""
        if text == '~':
            return True
        elif text.startswith('~') and len(text) > 1 and '/' not in text:
            return True
        return False

    def _handle_non_slash_path_completions(self, text: str, Completion: Any) -> Iterator[Any]:
        """Handle completions for paths without slashes."""
        if self._should_block_tilde_completion(text):
            return

        candidates: List[Path] = self._get_candidates(self.base_dir, True)
        matches: List[Tuple[str, float, Path]] = self._fuzzy_match(text, candidates)

        for name, score, path in matches:
            yield self._create_completion_for_path(path, -len(text), Completion)

    def _dispatch_completions_by_path_type(self, text: str, Completion: Any) -> Iterator[Any]:
        """Dispatch to appropriate completion handler based on path type (slash vs non-slash)."""
        if '/' in text:
            yield from self._handle_slash_path_completions(text, Completion)
        else:
            yield from self._handle_non_slash_path_completions(text, Completion)

    def get_completions(self, document: Any, complete_event: Any) -> Iterator[Any]:
        """
        Generate completions for the current document state.

        Args:
            document: The prompt_toolkit Document object
            complete_event: The completion event

        Yields:
            Completion objects for matching candidates
        """
        from prompt_toolkit.completion import Completion

        text: str = document.text_before_cursor
        yield from self._dispatch_completions_by_path_type(text, Completion)

    async def get_completions_async(self, document: Any, complete_event: Any) -> Any:
        """
        Async version of get_completions required by prompt_toolkit.

        Args:
            document: The prompt_toolkit Document object
            complete_event: The completion event

        Yields:
            Completion objects for matching candidates
        """
        # Delegate to synchronous version since our operations are fast
        for completion in self.get_completions(document, complete_event):
            yield completion

    def expand_path_if_unique(self, text: str) -> Optional[str]:
        """
        Expand path components if they match a single directory.
        Preserves ~ and $HOME prefixes.
        Returns the expanded path string or None if no unique expansion or no changes needed.
        """
        if not text or not text.endswith('/'):
            return None

        parts = text.split('/')
        # parts will end with empty string because of trailing slash

        current_dir = self.base_dir
        result_parts = []

        start_idx = 0
        if text.startswith('/'):
            current_dir = Path('/')
            result_parts.append('')
            start_idx = 1
        elif parts[0] in ('~', '$HOME'):
            current_dir = Path.home()
            result_parts.append(parts[0])
            start_idx = 1

        for i in range(start_idx, len(parts) - 1):
            part = parts[i]
            if not part:
                result_parts.append('')
                continue

            subdirs = self._get_candidates(current_dir, False)
            if not subdirs:
                return None

            matches = self._fuzzy_match(part, subdirs)

            if len(matches) == 1:
                name, score, path = matches[0]
                result_parts.append(name)
                current_dir = path
            else:
                return None

        expanded_path = '/'.join(result_parts) + '/'

        if expanded_path == text:
            return None

        return expanded_path


def detect_editing_mode_from_inputrc() -> str:
    """
    Detect editing mode (vi or emacs) from ~/.inputrc.

    Returns:
        'vi' or 'emacs' (defaults to 'emacs' if not specified or file doesn't exist)
    """
    inputrc_path: Path = Path.home() / '.inputrc'

    if not inputrc_path.exists():
        return 'emacs'

    try:
        content: str = inputrc_path.read_text()
        # Look for "set editing-mode vi" or "set editing-mode emacs"
        # Handle various whitespace and comment scenarios
        for line in content.splitlines():
            # Strip comments (everything after #)
            line = line.split('#')[0].strip()

            # Match "set editing-mode vi" or "set editing-mode emacs"
            match: Optional[re.Match[str]] = re.match(r'^set\s+editing-mode\s+(vi|emacs)\s*$', line, re.IGNORECASE)
            if match:
                return match.group(1).lower()
    except Exception:
        # If we can't read or parse the file, default to emacs
        pass

    return 'emacs'


def normalize_completion_flags(no_path_completion: bool, no_fuzzy: bool, enable_path_completion: bool) -> Tuple[bool, bool]:
    """Normalize completion flags based on no_path_completion setting."""
    if no_path_completion:
        return True, False
    return no_fuzzy, enable_path_completion


def select_editing_mode_by_string(mode_str: str, EditingMode: Any) -> Any:
    """Select editing mode enum value based on string."""
    if mode_str == 'vi':
        return EditingMode.VI
    else:
        return EditingMode.EMACS


def create_completer_for_path_mode(enable_path_completion: bool, no_fuzzy: bool) -> Optional[Any]:
    """Create completer based on path completion mode."""
    if enable_path_completion:
        base_dir = Path.cwd()
        return FuzzyPemCompleter(base_dir, no_fuzzy=no_fuzzy)
    else:
        return None
