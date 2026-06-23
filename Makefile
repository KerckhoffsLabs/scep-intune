.PHONY: build test lint tidy run
build:
	go build -o ./bin/scep-intune ./cmd/scep-intune
test:
	go test ./...
tidy:
	go mod tidy
run: build
	./bin/scep-intune -config config.example.yaml
