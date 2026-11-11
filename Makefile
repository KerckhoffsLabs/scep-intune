.PHONY: build test lint fmt tidy run e2e
build:
	go build -o ./bin/scep-intune ./cmd/scep-intune
test:
	go test ./...
lint:
	golangci-lint run
fmt:
	golangci-lint fmt
tidy:
	go mod tidy
run: build
	./bin/scep-intune -config config.example.yaml
# Full SCEP enrollment through step-ca, the bridge and the Intune mock (linux/amd64).
e2e:
	bash test/e2e/run.sh
