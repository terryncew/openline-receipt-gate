# OPENLINE-GATEWAY-001 Makefile

.PHONY: up up-opa-a up-opa-b down eval bench quickstart

up: ## Start the OpenLine gateway (profile: openline)
	cd compose && AUTH_MODE=openline docker compose --profile openline up --build -d
	@echo "Envoy on :8080. Run 'make eval' next."

up-opa-a: ## Start baseline A (ordinary OPA)
	cd compose && AUTH_MODE=opa OPA_POLICY=policy-a.rego docker compose --profile opa-a up --build -d

up-opa-b: ## Start baseline B (OPA with revocation list)
	cd compose && AUTH_MODE=opa OPA_POLICY=policy-b.rego docker compose --profile opa-b up --build -d

down: ## Stop everything
	cd compose && docker compose --profile openline --profile opa-a --profile opa-b down

eval: ## Run the 13 adversarial scenarios (needs 'make up' first)
	python3 scenarios/run_scenarios.py

bench: ## Latency benchmark (needs the target stack running)
	python3 bench/bench.py openline

quickstart: up eval ## Full reproducer path: up, then eval
	@echo "Done. See docs/QUICKSTART.md for what just happened."
