.PHONY: sync, test

sync:
	uv sync

test:
	uv run python -m unittest tests/*.py
