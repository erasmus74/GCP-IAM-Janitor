#!/bin/bash

# GCP IAM Janitor - Registry Deployment Script
# Uses pre-built images from GitHub Container Registry

set -e

# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
DEFAULT_APP_VERSION="advanced"
DEFAULT_PORT="8501"
REGISTRY="ghcr.io/erasmus74/gcp-iam-janitor"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}========================================${NC}"
    echo -e "${PURPLE} GCP IAM Janitor - Registry Deployment${NC}"
    echo -e "${PURPLE}========================================${NC}"
    echo
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Docker is installed and running
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    # Check if docker compose is available
    if ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not available. Please install Docker Compose."
        exit 1
    fi
    
    print_success "All prerequisites are met."
}

# Function to pull latest images
pull_images() {
    local app_version=${1:-$DEFAULT_APP_VERSION}
    
    if [ "$app_version" = "all" ]; then
        print_status "Pulling all images from registry..."
        docker pull "$REGISTRY:main-simple"
        docker pull "$REGISTRY:main-enhanced"
        docker pull "$REGISTRY:main-consolidation"  
        docker pull "$REGISTRY:main-advanced"
        print_success "All images pulled successfully!"
    else
        print_status "Pulling image: $REGISTRY:main-$app_version"
        docker pull "$REGISTRY:main-$app_version"
        print_success "Image pulled successfully!"
    fi
}

# Function to run using registry compose file
run_registry() {
    local app_version=${1:-$DEFAULT_APP_VERSION}
    
    print_status "Starting GCP IAM Janitor from registry..."
    print_status "App Version: $app_version"
    
    # Pull latest image first
    pull_images "$app_version"
    
    # Set APP_VERSION environment variable and run compose
    export APP_VERSION="$app_version"
    
    docker compose -f docker-compose.registry.yml up -d
    
    print_success "Container started successfully!"
    print_status "Access the application at: http://localhost:$DEFAULT_PORT"
    print_status "View logs with: $0 logs"
    print_status "Stop with: $0 stop"
}

# Function to run container directly from registry
run_direct_registry() {
    local app_version=${1:-$DEFAULT_APP_VERSION}
    local port=${2:-$DEFAULT_PORT}
    
    print_status "Running GCP IAM Janitor from registry..."
    
    # Pull latest image
    pull_images "$app_version"
    
    # Prepare volume mounts for GCP credentials
    local volume_mounts=""
    if [ -d "$HOME/.config/gcloud" ]; then
        volume_mounts="-v $HOME/.config/gcloud:/gcp/credentials:ro"
    fi
    
    # Set environment variables
    local env_vars=""
    env_vars="$env_vars -e APP_VERSION=$app_version"
    env_vars="$env_vars -e GOOGLE_APPLICATION_CREDENTIALS=/gcp/credentials/application_default_credentials.json"
    
    if [ -n "$GCP_PROJECT_ID" ]; then
        env_vars="$env_vars -e GCP_PROJECT_ID=$GCP_PROJECT_ID"
    fi
    
    docker run --rm -it \
        -p "$port:8501" \
        $volume_mounts \
        $env_vars \
        "$REGISTRY:main-$app_version"
}

# Function to stop containers
stop_containers() {
    print_status "Stopping all GCP IAM Janitor containers..."
    
    # Stop compose-managed containers
    docker compose -f docker-compose.registry.yml down 2>/dev/null
    
    # Stop any directly-run containers with our naming pattern
    local containers=$(docker ps --filter "name=gcp-iam-janitor" --format "{{.Names}}")
    
    if [ -n "$containers" ]; then
        print_status "Stopping direct containers: $containers"
        echo "$containers" | xargs -r docker stop
        echo "$containers" | xargs -r docker rm
    fi
    
    print_success "All containers stopped."
}

# Function to show logs
show_logs() {
    docker compose -f docker-compose.registry.yml logs -f
}

# Function to show container status
show_status() {
    print_status "Container status:"
    docker compose -f docker-compose.registry.yml ps
}

# Function to show help
show_help() {
    echo "GCP IAM Janitor - Registry Deployment Script"
    echo
    echo "Usage: $0 <command> [options]"
    echo
    echo "Commands:"
    echo "  run <version>      Run using Docker Compose with registry images"
    echo "  direct <version>   Run container directly from registry"
    echo "  pull <version>     Pull images from registry"
    echo "  stop              Stop all containers"
    echo "  logs              Show container logs"
    echo "  status            Show container status"
    echo "  help              Show this help message"
    echo
    echo "App Versions:"
    echo "  simple            Basic IAM analysis"
    echo "  enhanced          Advanced analytics with AI insights"
    echo "  consolidation     IAM policy reduction dashboard"
    echo "  advanced          Complete feature set (default)"
    echo "  all               Pull all versions (pull command only)"
    echo
    echo "Examples:"
    echo "  $0 run consolidation    # Run consolidation dashboard"
    echo "  $0 direct advanced      # Run advanced version directly"
    echo "  $0 pull all            # Pull all images"
    echo "  $0 stop                # Stop containers"
    echo
    echo "Registry: $REGISTRY"
}

# Main script logic
main() {
    print_header
    
    if [ $# -eq 0 ]; then
        show_help
        exit 0
    fi
    
    local command="$1"
    shift
    
    case "$command" in
        "run")
            check_prerequisites
            local app_version=${1:-$DEFAULT_APP_VERSION}
            run_registry "$app_version"
            ;;
        "direct")
            check_prerequisites
            local app_version=${1:-$DEFAULT_APP_VERSION}
            local port=${2:-$DEFAULT_PORT}
            run_direct_registry "$app_version" "$port"
            ;;
        "pull")
            check_prerequisites
            local app_version=${1:-$DEFAULT_APP_VERSION}
            pull_images "$app_version"
            ;;
        "stop")
            stop_containers
            ;;
        "logs")
            show_logs
            ;;
        "status")
            show_status
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Run the main function with all arguments
main "$@"