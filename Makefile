test:
	python -m unittest discover -s tests -v

proof:
	PYTHONPATH=. python tests/proof.py

serve:
	python -m guard.server serve
