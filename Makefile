# Thin shim so the conventional `make dev` works (R6). `just` is the real task
# runner — see the justfile. Install just: https://just.systems
.PHONY: dev build test vet fmt tidy

dev:
	just dev

build:
	just build

test:
	just test

vet:
	just vet

fmt:
	just fmt

tidy:
	just tidy
