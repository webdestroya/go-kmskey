
.PHONY: test
test:
	@go test -v -timeout 180s ./...

.PHONY: bench
bench:
	@go test -v -bench=. ./...

.PHONY: coverage
coverage:
	@mkdir -p coverage
	@go test -v ./... -coverpkg=./... -coverprofile=coverage/c.out -covermode=count -short
	@cat coverage/c.out > coverage/c_notest.out
	@go tool cover -html=coverage/c_notest.out -o coverage/index.html