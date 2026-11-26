PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
RUFF ?= .venv/bin/ruff
BANDIT ?= .venv/bin/bandit

.PHONY: test lint security case serve

test:
	$(PYTEST) -v --cov=src/vesper

lint:
	$(RUFF) check src tests scripts

security:
	$(BANDIT) -r src -q --severity-level high

case:
	$(PYTHON) scripts/run_vesper_case.py

serve:
	.venv/bin/uvicorn vesper.web:create_app --factory --host 127.0.0.1 --port 8006
