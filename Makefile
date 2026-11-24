.PHONY: unit pg test migrate
unit:
	python -m pytest -q tests --ignore=tests/postgres
pg:
	python -m pytest -q tests/postgres
test: unit pg
migrate:
	python tools/migrate_postgres.py
