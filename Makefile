
.PHONY: test
test:
	@go test -v -timeout 180s ./...

.PHONY: coverage
coverage:
	@mkdir -p coverage
	@go test -v ./... -coverpkg=./... -coverprofile=coverage/c.out -covermode=count -short
	@cat coverage/c.out > coverage/c_notest.out
	@go tool cover -html=coverage/c_notest.out -o coverage/index.html

.PHONY: lint
lint:
	@which golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found"; \
		exit 1; \
	}
	@golangci-lint version
	@golangci-lint run && echo "Code passed lint check!"