.PHONY: setup test type-check lint format format-check clean server test-integration

VENV := venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

setup: $(VENV)
	$(PIP) install -e ".[dev]"

$(VENV):
	python3 -m venv $(VENV)

test:
	$(VENV)/bin/pytest tests/test_api.py tests/test_token.py

type-check:
	$(VENV)/bin/mypy better_auth

lint:
	$(VENV)/bin/ruff check .

format:
	$(VENV)/bin/black .

format-check:
	$(VENV)/bin/black --check .

server:
	$(PYTHON) -m examples.server

test-integration:
	$(VENV)/bin/pytest tests/integration/test_integration.py

clean:
	rm -rf $(VENV) build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
