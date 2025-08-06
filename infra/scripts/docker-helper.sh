#!/bin/bash
# Spotter-SAST Docker Helper Scripts

# ===========================================
# build.sh - Build the Docker image
# ===========================================
build_image() {
    echo "🔨 Building Spotter-SAST Docker image..."
    
    # Create necessary directories
    mkdir -p docker-logs docker-reports
    
    # Build the image
    docker build -t spotter-sast:latest .
    
    if [ $? -eq 0 ]; then
        echo "✅ Docker image built successfully!"
        echo "📦 Image: spotter-sast:latest"
    else
        echo "❌ Docker build failed!"
        exit 1
    fi
}

# ===========================================
# run.sh - Run the container
# ===========================================
run_container() {
    local scan_path=${1:-$(pwd)}
    local container_name="spotter-sast-$(date +%s)"
    
    echo "🚀 Starting Spotter-SAST container..."
    echo "📂 Scanning path: $scan_path"
    
    # Create directories if they don't exist
    mkdir -p docker-logs docker-reports
    
    # Run the container
    docker run -d \
        --name "$container_name" \
        --restart unless-stopped \
        -v "$scan_path:/scan-target:ro" \
        -v "$(pwd)/docker-logs:/app/logs" \
        -v "$(pwd)/docker-reports:/app/reports" \
        -v "$(pwd)/config:/app/config:ro" \
        -p 3000:3000 \
        --env-file .env \
        spotter-sast:latest
    
    if [ $? -eq 0 ]; then
        echo "✅ Container started successfully!"
        echo "🆔 Container ID: $container_name"
        echo "📊 Logs: docker logs -f $container_name"
        echo "🔍 Scan results will be in: $(pwd)/docker-reports"
    else
        echo "❌ Failed to start container!"
        exit 1
    fi
}

# ===========================================
# scan.sh - Run a one-time scan
# ===========================================
run_scan() {
    local scan_path=${1:-$(pwd)}
    local output_format=${2:-"html"}
    
    echo "🔍 Running one-time security scan..."
    echo "📂 Scanning: $scan_path"
    echo "📄 Format: $output_format"
    
    # Create reports directory
    mkdir -p docker-reports
    
    # Run scan container
    docker run --rm \
        -v "$scan_path:/scan-target:ro" \
        -v "$(pwd)/docker-reports:/app/reports" \
        -v "$(pwd)/config:/app/config:ro" \
        --env-file .env \
        spotter-sast:latest \
        node server.js enhanced_scan_directory /scan-target --format="$output_format"
    
    if [ $? -eq 0 ]; then
        echo "✅ Scan completed successfully!"
        echo "📊 Results available in: $(pwd)/docker-reports"
    else
        echo "❌ Scan failed!"
        exit 1
    fi
}

# ===========================================
# interactive.sh - Run interactive container
# ===========================================
run_interactive() {
    local scan_path=${1:-$(pwd)}
    
    echo "🔧 Starting interactive Spotter-SAST container..."
    
    docker run -it --rm \
        -v "$scan_path:/scan-target:ro" \
        -v "$(pwd)/docker-logs:/app/logs" \
        -v "$(pwd)/docker-reports:/app/reports" \
        -v "$(pwd)/config:/app/config:ro" \
        --env-file .env \
        spotter-sast:latest \
        /bin/bash
}

# ===========================================
# clean.sh - Clean up Docker resources
# ===========================================
cleanup() {
    echo "🧹 Cleaning up Spotter-SAST Docker resources..."
    
    # Stop and remove containers
    docker ps -a | grep spotter-sast | awk '{print $1}' | xargs -r docker stop
    docker ps -a | grep spotter-sast | awk '{print $1}' | xargs -r docker rm
    
    # Remove unused images (optional)
    read -p "Remove unused Docker images? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker image prune -f
    fi
    
    echo "✅ Cleanup completed!"
}

# ===========================================
# status.sh - Check container status
# ===========================================
check_status() {
    echo "📊 Spotter-SAST Container Status:"
    echo "================================="
    
    # Show running containers
    echo "🏃 Running containers:"
    docker ps | grep spotter-sast || echo "   No running containers found"
    
    echo ""
    
    # Show all containers
    echo "📋 All containers:"
    docker ps -a | grep spotter-sast || echo "   No containers found"
    
    echo ""
    
    # Show images
    echo "🖼️ Images:"
    docker images | grep spotter-sast || echo "   No images found"
    
    echo ""
    
    # Show volumes
    echo "💾 Volumes:"
    ls -la docker-logs/ docker-reports/ 2>/dev/null || echo "   No volume directories found"
}

# ===========================================
# logs.sh - View container logs
# ===========================================
view_logs() {
    local container_name=${1:-$(docker ps | grep spotter-sast | head -n1 | awk '{print $NF}')}
    
    if [ -z "$container_name" ]; then
        echo "❌ No running Spotter-SAST containers found"
        exit 1
    fi
    
    echo "📋 Viewing logs for: $container_name"
    docker logs -f "$container_name"
}

# ===========================================
# Main script logic
# ===========================================
case "${1:-help}" in
    "build")
        build_image
        ;;
    "run")
        run_container "$2"
        ;;
    "scan")
        run_scan "$2" "$3"
        ;;
    "interactive"|"shell")
        run_interactive "$2"
        ;;
    "clean"|"cleanup")
        cleanup
        ;;
    "status")
        check_status
        ;;
    "logs")
        view_logs "$2"
        ;;
    "help"|*)
        echo "🔍 Spotter-SAST Docker Helper"
        echo "=============================="
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  build                 - Build the Docker image"
        echo "  run [scan_path]       - Run persistent container (default: current directory)"
        echo "  scan [path] [format]  - Run one-time scan (default: current dir, html format)"
        echo "  interactive [path]    - Start interactive shell in container"  
        echo "  status                - Show container and image status"
        echo "  logs [container]      - View container logs"
        echo "  clean                 - Clean up containers and images"
        echo "  help                  - Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 build"
        echo "  $0 run /path/to/your/code"
        echo "  $0 scan /path/to/code sarif"
        echo "  $0 interactive"
        echo "  $0 status"
        echo ""
        echo "📁 Results will be saved to: $(pwd)/docker-reports"
        echo "📋 Logs will be saved to: $(pwd)/docker-logs"
        ;;
esac