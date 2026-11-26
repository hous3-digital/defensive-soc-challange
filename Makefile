VECTOR_IMAGE ?= timberio/vector:0.62.0-distroless-static

.PHONY: up down clean logs test test-proxy test-vector smoke

up:
	docker compose up -d --build

down:
	docker compose down

clean:
	docker compose down -v

logs:
	docker compose logs -f

test: test-proxy test-vector

test-proxy:
	cd services/dashboards/access-proxy && go test ./...

test-vector:
	docker run --rm \
		-e VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
		-e COLLECTOR_USERNAME=test -e COLLECTOR_PASSWORD=test \
		-e OPENSEARCH_HOSTPORT=opensearch:9200 -e COLLECTOR_HOSTPORT=collector:8080 \
		-v $(CURDIR)/services:/services:ro \
		$(VECTOR_IMAGE) test \
		/services/collector/vector/vector.yaml /services/collector/vector/tests.yaml
	docker run --rm \
		-e VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true \
		-e COLLECTOR_USERNAME=test -e COLLECTOR_PASSWORD=test -e COLLECTOR_HOSTPORT=collector:8080 \
		-v $(CURDIR)/services:/services:ro \
		$(VECTOR_IMAGE) validate --no-environment /services/edge/vector/vector.yaml

smoke:
	./scripts/smoke-test.sh
