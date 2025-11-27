from pathlib import Path
from typing import List, Optional, Tuple, Callable, Any
from gh_tokengen.utils import natural_sort_key

def make_path_absolute_from_cwd(path: Path, cwd: Path) -> Path:
    """Make path absolute if relative, using current working directory."""
    return path if path.is_absolute() else cwd / path


def determine_base_directory_for_text(text: str, cwd: Path) -> Path:
    """
    Determine the base directory based on text prefix.

    Args:
        text: The input text containing the path
        cwd: Current working directory to use for relative paths

    Returns:
        Path object representing the base directory
    """
    if text.startswith('/'):
        return Path('/')
    elif text.startswith('~/') or text.startswith('$HOME/'):
        return Path.home()
    else:
        return cwd
def expand_home_in_path(text: str) -> Path:
    """Expand $HOME and ~ in path string."""
    expanded = text.replace('$HOME', str(Path.home()))
    return Path(expanded).expanduser()


def has_ordered_characters_match(query_str: str, target_str: str) -> bool:
    """Check if query characters appear in order in target (case-insensitive)."""
    query_lower = query_str.lower()
    target_lower = target_str.lower()
    query_idx = 0
    for char in target_lower:
        query_idx += (query_idx < len(query_lower) and char == query_lower[query_idx])
    return query_idx == len(query_lower)


def find_prefix_matches_case_sensitive(query: str, candidates: List[Path]) -> List[Path]:
    """Find candidates matching query prefix with case sensitivity."""
    return [c for c in candidates if c.name.startswith(query)]


def find_prefix_matches_case_insensitive(query: str, candidates: List[Path]) -> List[Path]:
    """Find candidates matching query prefix without case sensitivity."""
    query_lower = query.lower()
    return [c for c in candidates if c.name.lower().startswith(query_lower)]


def select_prefix_matching_strategy(query: str, candidates: List[Path]) -> List[Path]:
    """Select and apply prefix matching strategy based on query case."""
    query_has_upper = any(c.isupper() for c in query)
    return find_prefix_matches_case_sensitive(query, candidates) if query_has_upper else find_prefix_matches_case_insensitive(query, candidates)


def find_fuzzy_matches(query: str, candidates: List[Path]) -> List[Path]:
    """Find candidates matching query using fuzzy (ordered characters) matching."""
    return [c for c in candidates if has_ordered_characters_match(query, c.name)]


def apply_matching_strategy(query: str, candidates: List[Path], no_fuzzy: bool) -> List[Path]:
    """Apply appropriate matching strategy (prefix or fuzzy) based on mode."""
    return select_prefix_matching_strategy(query, candidates) if no_fuzzy else find_fuzzy_matches(query, candidates)


def match_query_against_target(query_str: str, target_str: str, no_fuzzy: bool) -> bool:
    """Match query against target based on current fuzzy mode setting."""
    if no_fuzzy:
        # Prefix matching logic
        query_has_upper = any(c.isupper() for c in query_str)
        if query_has_upper:
            return target_str.startswith(query_str)
        else:
            return target_str.lower().startswith(query_str.lower())
    else:
        # Fuzzy matching logic
        return has_ordered_characters_match(query_str, target_str)


def find_exact_directory_match(subdirs: List[Path], part: str) -> Optional[Path]:
    """Find exact name match in subdirectory list."""
    for subdir in subdirs:
        if subdir.name == part:
            return subdir
    return None


def find_first_matching_directory(subdirs: List[Path], part: str, no_fuzzy: bool) -> Optional[Path]:
    """Find first matching subdirectory using current matching strategy."""
    matches = apply_matching_strategy(part, subdirs, no_fuzzy)
    if matches:
        return matches[0]
    else:
        return None


def resolve_directory_segment(subdirs: List[Path], part: str, no_fuzzy: bool) -> Optional[Path]:
    """Resolve a path segment to a matched directory."""
    exact = find_exact_directory_match(subdirs, part)
    if exact:
        return exact
    else:
        return find_first_matching_directory(subdirs, part, no_fuzzy)


def get_subdirectories_from_path(current_dir: Path) -> List[Path]:
    """Get list of subdirectories from path, empty list if path doesn't exist."""
    if current_dir.exists():
        return [p for p in current_dir.iterdir() if p.is_dir()]
    else:
        return []


def check_skip_directory_part(i: int, part: str) -> bool:
    """Determine if directory part should be skipped during navigation."""
    if not part:
        return True
    if i == 0 and part in ('~', '$HOME'):
        return True
    return False


def navigate_one_directory_segment(current_path: Path, part: str, no_fuzzy: bool) -> Optional[Path]:
    """Navigate through one directory segment."""
    subdirs = get_subdirectories_from_path(current_path)
    return resolve_directory_segment(subdirs, part, no_fuzzy)


def navigate_through_directory_parts(base_dir: Path, parts: List[str], no_fuzzy: bool) -> Optional[Path]:
    """
    Navigate through all provided directory parts.

    Args:
        base_dir: The starting directory
        parts: List of directory parts to navigate
        no_fuzzy: Whether to use fuzzy matching

    Returns:
        The final directory Path if successful, None otherwise.
    """
    current_dir = base_dir
    for i, part in enumerate(parts):
        if check_skip_directory_part(i, part):
            continue

        matched = navigate_one_directory_segment(current_dir, part, no_fuzzy)
        if matched:
            current_dir = matched
        else:
            return None
    return current_dir


class FuzzyPathResolver:
    """Resolves fuzzy path input to actual filesystem paths."""

    def __init__(self, cwd: Path, no_fuzzy: bool, enable_path_completion: bool) -> None:
        """
        Initialize the resolver.

        Args:
            cwd: Current working directory
            no_fuzzy: Whether to use fuzzy matching
            enable_path_completion: Whether path completion is enabled
        """
        self.cwd = cwd
        self.no_fuzzy = no_fuzzy
        self.enable_path_completion = enable_path_completion
        try:
            from rapidfuzz import fuzz, process
            self.fuzz: Any = fuzz
            self.process: Any = process
        except ImportError:
            self.fuzz = None
            self.process = None

    def _collect_directory_candidates(self, directory: Path) -> List[Path]:
        """Collect directory items from a path, returning empty list if unavailable."""
        return [item for item in directory.iterdir() if item.is_dir()] if directory.exists() else []

    def _collect_final_segment_candidates(self, directory: Path) -> List[Path]:
        """Collect both directories and .pem files from a path."""
        return [item for item in directory.iterdir()
               if item.is_dir() or (item.is_file() and item.suffix.lower() == '.pem')] if directory.exists() else []

    def _collect_candidates_for_segment(self, directory: Path, is_final_segment: bool) -> List[Path]:
        """Collect candidates based on whether this is the final path segment."""
        return self._collect_final_segment_candidates(directory) if is_final_segment else self._collect_directory_candidates(directory)

    def _find_exact_match(self, candidates: List[Path], name: str) -> Optional[Path]:
        """Find exact name match in candidate list."""
        return next((c for c in candidates if c.name == name), None)

    def _filter_candidates_by_query(self, candidates: List[Path], query: str) -> List[Path]:
        """Filter candidates to those matching the query."""
        return [c for c in candidates if match_query_against_target(query, c.name, self.no_fuzzy)]

    def _select_first_candidate(self, candidates: List[Path]) -> Path:
        """Select the first candidate from a list."""
        return candidates[0]

    def _score_and_select_best_fuzzy_match(self, candidates: List[Path], query: str) -> Optional[Path]:
        """Score candidates and return the best fuzzy match."""
        if not self.process or not self.fuzz:
            return None
        names: List[str] = [c.name for c in candidates]
        matches: List[Tuple[str, float, int]] = self.process.extract(query, names, scorer=self.fuzz.QRatio, limit=1)
        return next((c for c in candidates if c.name == matches[0][0]), None) if matches else None

    def _select_best_fuzzy_candidate(self, candidates: List[Path], query: str) -> Path:
        """Select best candidate using fuzzy scoring."""
        return self._score_and_select_best_fuzzy_match(candidates, query) or candidates[0]

    def _select_candidate_by_mode(self, candidates: List[Path], query: str) -> Path:
        """Select best candidate based on current fuzzy mode setting."""
        return self._select_first_candidate(candidates) if self.no_fuzzy else self._select_best_fuzzy_candidate(candidates, query)

    def _resolve_segment_match(self, candidates: List[Path], segment: str) -> Optional[Path]:
        """Resolve a path segment to a matched candidate path."""
        exact = self._find_exact_match(candidates, segment)
        return exact or (lambda filtered: self._select_candidate_by_mode(filtered, segment) if filtered else None)(self._filter_candidates_by_query(candidates, segment))

    def _determine_root_for_absolute_path(self) -> Tuple[Path, int, List[str]]:
        """Determine base directory for absolute paths starting with /."""
        return (Path('/'), 1, [''])

    def _determine_root_for_tilde_path(self) -> Tuple[Path, int, List[str]]:
        """Determine base directory for paths starting with ~/."""
        return (Path.home(), 1, ['~'])

    def _determine_root_for_home_path(self) -> Tuple[Path, int, List[str]]:
        """Determine base directory for paths starting with $HOME/."""
        return (Path.home(), 1, ['$HOME'])

    def _determine_root_for_relative_path(self) -> Tuple[Path, int, List[str]]:
        """Determine base directory for relative paths."""
        return (self.cwd, 0, [])

    def _select_path_root_handler(self, text: str) -> Callable[[], Tuple[Path, int, List[str]]]:
        """Select the appropriate root handler based on path prefix."""
        starts_with_tilde = text.startswith('~/')
        starts_with_home = text.startswith('$HOME/')
        starts_with_slash = text.startswith('/')

        return (self._determine_root_for_absolute_path if starts_with_slash else
               self._determine_root_for_tilde_path if starts_with_tilde else
               self._determine_root_for_home_path if starts_with_home else
               self._determine_root_for_relative_path)

    def _initialize_path_navigation(self, text: str) -> Tuple[Path, int, List[str]]:
        """Initialize base directory, start index, and unexpanded parts for path navigation."""
        handler = self._select_path_root_handler(text)
        return handler()

    def _skip_empty_or_special_part(self, part: str) -> bool:
        """Determine if a path part should be skipped during navigation."""
        return not part or part in ('~', '$HOME')

    def _build_formatted_path_result(self, unexpanded_parts: List[str], resolved_path: Path) -> Tuple[str, str]:
        """Build the final result tuple with unexpanded and expanded paths."""
        unexpanded = '/'.join(unexpanded_parts)
        return (unexpanded, str(resolved_path))

    def _navigate_through_path_segments(self, parts: List[str], start_idx: int, initial_dir: Path, unexpanded_parts: List[str]) -> Optional[Tuple[Path, List[str]]]:
        """Navigate through all path segments, resolving each one."""
        current_dir = initial_dir

        for i in range(start_idx, len(parts)):
            part = parts[i]

            if self._skip_empty_or_special_part(part):
                continue

            is_final = (i == len(parts) - 1)
            candidates = self._collect_candidates_for_segment(current_dir, is_final)
            matched = self._resolve_segment_match(candidates, part)

            if not matched:
                return None

            current_dir = matched
            unexpanded_parts.append(matched.name)

        return (current_dir, unexpanded_parts)

    def _resolve_multi_segment_path(self, text: str) -> Optional[Tuple[str, str]]:
        """Resolve a path with multiple segments (contains /)."""
        parts = text.split('/')
        current_dir, start_idx, unexpanded_parts = self._initialize_path_navigation(text)
        navigation_result = self._navigate_through_path_segments(parts, start_idx, current_dir, unexpanded_parts)
        return self._build_formatted_path_result(navigation_result[1], navigation_result[0]) if navigation_result else None

    def _resolve_single_segment_path(self, text: str) -> Optional[Tuple[str, str]]:
        """Resolve a simple path with no directory separators."""
        base_dir = self.cwd
        candidates = self._collect_final_segment_candidates(base_dir)
        exact = self._find_exact_match(candidates, text)

        if exact:
            return (text, str(exact))

        filtered = self._filter_candidates_by_query(candidates, text)
        return ((lambda m: (m.name, str(m)))(self._select_candidate_by_mode(filtered, text))) if filtered else None

    def _dispatch_path_resolution(self, text: str) -> Optional[Tuple[str, str]]:
        """Dispatch to appropriate path resolution strategy based on path structure."""
        return self._resolve_multi_segment_path(text) if '/' in text else self._resolve_single_segment_path(text)

    def _resolve_path_with_error_handling(self, text: str) -> Optional[Tuple[str, str]]:
        """Resolve path with exception handling, returning None on any error."""
        try:
            return self._dispatch_path_resolution(text)
        except Exception:
            return None

    def _validate_path_resolution_preconditions(self, text: str) -> bool:
        """Check if preconditions for path resolution are met."""
        return bool(text and self.enable_path_completion)

    def resolve(self, text: str) -> Optional[Tuple[str, str]]:
        """
        Resolve a fuzzy path to an actual full path.

        Returns:
            Tuple of (unexpanded_path, expanded_path) or None if no match
        """
        return self._resolve_path_with_error_handling(text) if self._validate_path_resolution_preconditions(text) else None


