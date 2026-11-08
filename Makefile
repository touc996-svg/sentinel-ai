.PHONY: install test run docker-up docker-down

install:
	python -m pip install -r requirements.txt

test:
	python -m pytest -q

run:
	uvicorn app.main:app --reload

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down
