build-kms-client: ## Build the KMS client
	@echo "Building KMS client..."
	@GOOS=linux GOARCH=amd64 go build -o kms-client-linux-amd64 cmd/kms-client/main.go
	@echo "KMS client built successfully!"

generate-kms-mocks: ## Generate mocks for KMS interfaces
	@echo "Generating KMS mocks..."
	@go generate ./...
	@echo "KMS mocks generated successfully!"

test-kms:
	@echo "Running KMS tests..."
	@go test ./...
	@echo "KMS tests completed successfully!"