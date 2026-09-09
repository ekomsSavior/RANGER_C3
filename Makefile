# Ranger C3 Makefile
.PHONY: all build c2 implant stager clean deploy

BUILD_DIR ?= ./build
GOFLAGS ?= -ldflags="-s -w"

all: build

build: c2 implant stager

c2:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/ranger-c2 ./cmd/c2
	@echo "[+] C2 server built: $(BUILD_DIR)/ranger-c2"

implant:
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/implant.exe ./cmd/implant
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/implant ./cmd/implant
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/implant_mac ./cmd/implant
	@echo "[+] Implants built: $(BUILD_DIR)/implant*"

stager:
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/stager.exe ./cmd/stager
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/stager ./cmd/stager
	@echo "[+] Stagers built: $(BUILD_DIR)/stager*"

build-all: build
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(BUILD_DIR)/ranger-c2-arm64 ./cmd/c2
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(BUILD_DIR)/implant-arm64 ./cmd/implant
	GOOS=linux GOARCH=386 go build $(GOFLAGS) -o $(BUILD_DIR)/implant-386 ./cmd/implant
	GOOS=android GOARCH=arm64 go build $(GOFLAGS) -o $(BUILD_DIR)/implant-android ./cmd/implant
	@echo "[+] Cross-compiled builds done"

clean:
	rm -rf $(BUILD_DIR) certs/ data/

# Deploy C2 with default config
deploy-c2: c2
	@echo "[*] Starting C2 server..."
	./$(BUILD_DIR)/ranger-c2 \
		--listen :4443 \
		--mesh :9000 \
		--password "changeme" \
		--db data/c2.db \
		--gen-certs \
		--id ranger-c2-01

# Show binary sizes
sizes:
	@ls -lh $(BUILD_DIR)/ 2>/dev/null || echo "build first"

# Upstream deps
deps:
	go mod tidy
	go mod download
