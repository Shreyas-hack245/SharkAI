PY ?= python3
VENV ?= .venv
BIN = $(VENV)/bin

.PHONY: setup run test sample clean
setup:            ## create a virtualenv and install everything
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -r requirements-dev.txt

run:              ## start SharkAI on http://127.0.0.1:8000
	$(BIN)/python -m sharkai

test:             ## run the test-suite
	$(BIN)/python -m pytest -q

sample:           ## write samples/demo-ctf.pcap (5 hidden flags)
	$(BIN)/python scripts/make_sample.py

clean:
	rm -rf $(VENV) .pytest_cache data
