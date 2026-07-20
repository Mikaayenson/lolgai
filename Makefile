#!/usr/bin/env make
.PHONY: validate build serve

validate:
	python3 bin/validate.py

build: validate
	python3 bin/site.py

serve: build
	cd website && python3 -m http.server 8765
