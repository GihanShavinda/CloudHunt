.PHONY: install test run demo eval-demo privesc-demo detect-demo case-demo respond-demo up down
install:
	pip install -e ".[dev]"
test:
	pytest
run:
	uvicorn cloudhunt.api.main:app --reload
demo:
	python scripts/ingest_demo.py
eval-demo:
	python scripts/eval_demo.py
privesc-demo:
	python scripts/privesc_demo.py
detect-demo:
	python scripts/detect_demo.py
case-demo:
	python scripts/case_demo.py
respond-demo:
	python scripts/respond_demo.py
up:
	docker compose up --build
down:
	docker compose down -v
