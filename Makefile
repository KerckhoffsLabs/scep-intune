.PHONY: build test lint fmt tidy run
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
