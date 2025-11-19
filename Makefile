.PHONY: help ruff ruff-fix mypy

# Default target - show help
help:
	@echo "Available targets:"
	@echo "  ruff      - Run ruff linter to check code"
	@echo "  ruff-fix  - Run ruff linter and automatically fix issues"
	@echo "  mypy      - Run mypy type checker"

ruff:
	uv run ruff check

ruff-fix:
	uv run ruff check --fix

mypy:
	uv run mypy .
