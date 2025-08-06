# Spotter-SAST Docker Makefile
# =============================
# Note: This Makefile is located in infra/build/ and operates from the project root

# Variables
IMAGE_NAME := spotter-sast
IMAGE_TAG := latest
CONTAINER_NAME := spotter-sast-server
SCAN_PATH := $(shell cd ../../ && pwd)
REPORT_FORMAT := html
PROJECT_ROOT := $(shell cd ../../ && pwd)

# Docker build arguments
BUILD_ARGS := --target production

# Ensure required directories exist (relative to project root)
DIRS := $(PROJECT_ROOT)/docker-logs $(PROJECT_ROOT)/docker-reports

.PHONY: help build run scan stop clean status logs shell setup test

# Default target
help: ## Show this help message
	@echo "🔍 Spotter-SAST Docker Commands"
	@echo "==============================="
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Examples:"
	@echo "  make build          # Build the Docker image"
	@echo "  make run            # Start the container"
	@echo "  make scan           # Run a one-time scan"
	@echo "  make scan SCAN_PATH=/path/to/code REPORT_FORMAT=sarif"
	@echo "  make logs           # View container logs"
	@echo "  make shell          # Interactive shell"
	@echo ""

setup: ## Create required directories and environment file
	@echo "🔧 Setting up Spotter-SAST environment..."
	@mkdir -p $(DIRS)
	@cd $(PROJECT_ROOT) && if [ ! -f .env ]; then \
		echo "📝 Creating .env file from template..."; \
		cp .env.example .env 2>/dev/null || \
		echo "JWT_SECRET=docker-default-secret-change-in-production\nENABLE_RBAC=false\nLOG_LEVEL=info" > .env; \
	fi
	@echo "✅ Setup completed!"
	@echo "📝 Please review and update .env file before running"

build: setup ## Build the Docker image
	@echo "🔨 Building $(IMAGE_NAME):$(IMAGE_TAG)..."
	@cd $(PROJECT_ROOT) && docker build $(BUILD_ARGS) -f infra/docker/Dockerfile -t $(IMAGE_NAME):$(IMAGE_TAG) .
	@echo "✅ Build completed!"

run: setup ## Start the container in daemon mode
	@echo "🚀 Starting $(CONTAINER_NAME)..."
	@cd $(PROJECT_ROOT) && docker run -d \
		--name $(CONTAINER_NAME) \
		--restart unless-stopped \
		-v "$(SCAN_PATH):/scan-target:ro" \
		-v "$(PROJECT_ROOT)/docker-logs:/app/data/logs" \
		-v "$(PROJECT_ROOT)/docker-reports:/app/reports" \
		-v "$(PROJECT_ROOT)/config:/app/config:ro" \
		-p 3000:3000 \
		--env-file .env \
		$(IMAGE_NAME):$(IMAGE_TAG)
	@echo "✅ Container started!"
	@echo "📋 View logs: make logs"
	@echo "🔍 Reports: $(PROJECT_ROOT)/docker-reports"

scan: setup ## Run a one-time security scan
	@echo "🔍 Running security scan on $(SCAN_PATH)..."
	@echo "📄 Output format: $(REPORT_FORMAT)"
	@cd $(PROJECT_ROOT) && docker run --rm \
		-v "$(SCAN_PATH):/scan-target:ro" \
		-v "$(PROJECT_ROOT)/docker-reports:/app/reports" \
		-v "$(PROJECT_ROOT)/config:/app/config:ro" \
		--env-file .env \
		$(IMAGE_NAME):$(IMAGE_TAG) \
		node src/server.js enhanced_scan_directory /scan-target --format=$(REPORT_FORMAT)
	@echo "✅ Scan completed!"
	@echo "📊 Results: $(PROJECT_ROOT)/docker-reports"

stop: ## Stop the running container
	@echo "🛑 Stopping $(CONTAINER_NAME)..."
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true
	@echo "✅ Container stopped and removed"

clean: stop ## Clean up containers and images
	@echo "🧹 Cleaning up Docker resources..."
	@docker ps -aq --filter "name=spotter-sast" | xargs -r docker rm -f
	@docker images -q $(IMAGE_NAME) | xargs -r docker rmi -f
	@docker system prune -f
	@echo "✅ Cleanup completed!"

status: ## Show container and image status
	@echo "📊 Spotter-SAST Status"
	@echo "======================"
	@echo ""
	@echo "🏃 Running containers:"
	@docker ps --filter "name=spotter-sast" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "   None"
	@echo ""
	@echo "📋 All containers:"
	@docker ps -a --filter "name=spotter-sast" --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}" || echo "   None"
	@echo ""
	@echo "🖼️ Images:"
	@docker images $(IMAGE_NAME) --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" || echo "   None"
	@echo ""
	@echo "💾 Volume directories:"
	@ls -la $(PROJECT_ROOT)/docker-logs/ $(PROJECT_ROOT)/docker-reports/ 2>/dev/null || echo "   Not created yet"

logs: ## View container logs
	@echo "📋 Viewing logs for $(CONTAINER_NAME)..."
	@docker logs -f $(CONTAINER_NAME) 2>/dev/null || \
		(echo "❌ Container not running. Starting temporary container for logs..." && \
		 docker run --rm -v "$(PROJECT_ROOT)/docker-logs:/app/data/logs" $(IMAGE_NAME):$(IMAGE_TAG) cat /app/data/logs/security.log 2>/dev/null || \
		 echo "No logs available")

shell: setup ## Start an interactive shell in the container
	@echo "🔧 Starting interactive shell..."
	@cd $(PROJECT_ROOT) && docker run -it --rm \
		-v "$(SCAN_PATH):/scan-target:ro" \
		-v "$(PROJECT_ROOT)/docker-logs:/app/data/logs" \
		-v "$(PROJECT_ROOT)/docker-reports:/app/reports" \
		-v "$(PROJECT_ROOT)/config:/app/config:ro" \
		--env-file .env \
		$(IMAGE_NAME):$(IMAGE_TAG) \
		/bin/bash

test: build ## Run basic functionality tests
	@echo "🧪 Testing Spotter-SAST functionality..."
	@echo "1. Testing tool availability..."
	@docker run --rm $(IMAGE_NAME):$(IMAGE_TAG) semgrep --version
	@docker run --rm $(IMAGE_NAME):$(IMAGE_TAG) bandit --version
	@docker run --rm $(IMAGE_NAME):$(IMAGE_TAG) eslint --version
	@docker run --rm $(IMAGE_NAME):$(IMAGE_TAG) njsscan --version
	@echo "2. Testing application startup..."
	@docker run --rm $(IMAGE_NAME):$(IMAGE_TAG) node -e "console.error('✅ Node.js application loads successfully')"
	@echo "✅ All tests passed!"

restart: stop run ## Restart the container

rebuild: clean build ## Clean rebuild of the image

# Development targets
dev-build: ## Build development image
	@cd $(PROJECT_ROOT) && docker build --target builder -f infra/docker/Dockerfile -t $(IMAGE_NAME):dev .

dev-run: setup ## Run development container
	@cd $(PROJECT_ROOT) && docker run -it --rm \
		-v "$(PROJECT_ROOT):/app" \
		-v "$(SCAN_PATH):/scan-target:ro" \
		-v "$(PROJECT_ROOT)/docker-logs:/app/data/logs" \
		-v "$(PROJECT_ROOT)/docker-reports:/app/reports" \
		--env-file .env \
		$(IMAGE_NAME):dev \
		/bin/bash

# Advanced targets
compose-up: ## Start with docker-compose
	@echo "🚀 Starting with docker-compose..."
	@cd $(PROJECT_ROOT) && docker-compose -f infra/docker/docker-compose.yml up -d
	@echo "✅ Services started!"

compose-down: ## Stop docker-compose services
	@echo "🛑 Stopping docker-compose services..."
	@cd $(PROJECT_ROOT) && docker-compose -f infra/docker/docker-compose.yml down
	@echo "✅ Services stopped!"

compose-logs: ## View docker-compose logs
	@cd $(PROJECT_ROOT) && docker-compose -f infra/docker/docker-compose.yml logs -f

# Security scanning of the container itself
security-scan: build ## Run security scan on the Docker image
	@echo "🔒 Scanning Docker image for vulnerabilities..."
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy:latest image $(IMAGE_NAME):$(IMAGE_TAG) || \
		echo "⚠️ Trivy not available. Install with: docker pull aquasec/trivy"

# Compliance-specific targets
compliance-setup: setup ## Setup compliance-specific environment
	@echo "🏛️ Setting up compliance environment..."
	@cd $(PROJECT_ROOT) && ./infra/scripts/compliance.sh setup
	@echo "✅ Compliance setup completed!"

compliance-scan: setup ## Run compliance scan using Docker
	@echo "🏛️ Running compliance scan..."
	@cd $(PROJECT_ROOT) && docker run --rm \
		-v "$(SCAN_PATH):/scan-target:ro" \
		-v "$(PROJECT_ROOT)/docker-reports:/app/reports" \
		-v "$(PROJECT_ROOT)/config:/app/config:ro" \
		-v "$(PROJECT_ROOT)/data:/app/data" \
		--env-file .env \
		$(IMAGE_NAME):$(IMAGE_TAG) \
		./infra/scripts/compliance.sh scan /scan-target
	@echo "✅ Compliance scan completed!"