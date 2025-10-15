#!/bin/bash

# GCP IAM Janitor - Docker Deployment Helper Script
# This script provides simplified commands for building, running, and managing
# the GCP IAM Janitor Docker containers.

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
DEFAULT_ENVIRONMENT="development"
DEFAULT_PORT="8501"

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
    echo -e "${PURPLE}================================${NC}"
    echo -e "${PURPLE} GCP IAM Janitor - Docker Deploy${NC}"
    echo -e "${PURPLE}================================${NC}"
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

# Function to validate environment variables
validate_environment() {
    print_status "Validating environment configuration..."
    
    # Check for required environment variables or .env file
    if [ ! -f ".env" ] && [ -z "$GCP_PROJECT_ID" ]; then
        print_warning "No .env file found and GCP_PROJECT_ID not set."
        print_status "You can:"
        echo "  1. Copy .env.example to .env and configure it"
        echo "  2. Set environment variables manually"
        echo "  3. Continue anyway (you'll need to configure GCP access later)"
        echo
        read -p "Do you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Exiting. Please configure your environment first."
            exit 1
        fi
    fi
    
    # Check for GCP credentials
    if [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ] && [ ! -d "$HOME/.config/gcloud" ]; then
        print_warning "Google Cloud credentials not detected."
        print_status "Make sure you have run: gcloud auth application-default login"
        print_status "Or set GOOGLE_APPLICATION_CREDENTIALS to your service account key file."
    fi
    
    print_success "Environment validation completed."
}

# Function to build Docker image
build_image() {
    local app_version=${1:-$DEFAULT_APP_VERSION}
    local no_cache=${2:-false}
    
    print_status "Building Docker image for app version: $app_version"
    
    local build_args=""
    if [ "$no_cache" = true ]; then
        build_args="--no-cache"
    fi
    
    docker build $build_args \
        --build-arg APP_VERSION="$app_version" \
        -t "gcp-iam-janitor:$app_version" \
        -t "gcp-iam-janitor:latest" \
        .
    
    print_success "Docker image built successfully: gcp-iam-janitor:$app_version"
}

# Function to run container using docker compose
run_compose() {
    local app_version=${1:-$DEFAULT_APP_VERSION}
    local environment=${2:-$DEFAULT_ENVIRONMENT}
    local detached=${3:-true}
    
    print_status "Starting GCP IAM Janitor using Docker Compose..."
    print_status "App Version: $app_version"
    print_status "Environment: $environment"
    
    export APP_VERSION="$app_version"
    
    local compose_file="docker-compose.yml"
    local compose_args=""
    
    # Select compose file based on environment
    if [ "$environment" = "production" ]; then
        compose_file="docker-compose.prod.yml"
    fi
    
    # Select profile based on app version
    if [ "$app_version" != "advanced" ]; then
        compose_args="--profile $app_version"
    fi
    
    # Run in detached mode by default
    local run_args=""
    if [ "$detached" = true ]; then
        run_args="-d"
    fi
    
    docker compose -f "$compose_file" $compose_args up $run_args
    
    if [ "$detached" = true ]; then
        print_success "Container started successfully!"
        print_status "Access the application at: http://localhost:$DEFAULT_PORT"
        print_status "View logs with: $0 logs"
        print_status "Stop with: $0 stop"
    fi
}

# Function to run container directly with docker
run_direct() {
    local app_version=${1:-$DEFAULT_APP_VERSION}
    local port=${2:-$DEFAULT_PORT}
    
    print_status "Running GCP IAM Janitor container directly..."
    
    # Check if image exists
    if ! docker image inspect "gcp-iam-janitor:$app_version" &> /dev/null; then
        print_status "Image not found locally. Building..."
        build_image "$app_version"
    fi
    
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
        "gcp-iam-janitor:$app_version"
}

# Function to stop containers
stop_containers() {
    print_status "Stopping all GCP IAM Janitor containers..."
    
    # Stop compose containers
    if [ -f "docker-compose.yml" ]; then
        docker compose -f docker-compose.yml down 2>/dev/null || true
    fi
    
    if [ -f "docker-compose.prod.yml" ]; then
        docker compose -f docker-compose.prod.yml down 2>/dev/null || true
    fi
    
    # Stop any running containers
    docker ps --filter "ancestor=gcp-iam-janitor" --format "table {{.ID}}" | grep -v CONTAINER | xargs -r docker stop
    
    print_success "All containers stopped."
}

# Function to show logs
show_logs() {
    local follow=${1:-false}
    
    print_status "Showing container logs..."
    
    local log_args=""
    if [ "$follow" = true ]; then
        log_args="-f"
    fi
    
    # Try compose first
    if docker compose ps | grep -q "gcp-iam-janitor"; then
        docker compose logs $log_args
    else
        # Fallback to direct container logs
        local container_id=$(docker ps --filter "ancestor=gcp-iam-janitor" --format "{{.ID}}" | head -n 1)
        if [ -n "$container_id" ]; then
            docker logs $log_args "$container_id"
        else
            print_error "No running containers found."
            exit 1
        fi
    fi
}

# Function to show container status
show_status() {
    print_status "Container Status:"
    echo
    
    # Show compose services
    if [ -f "docker-compose.yml" ]; then
        echo "Development environment:"
        docker compose -f docker-compose.yml ps 2>/dev/null || echo "  No services running"
        echo
    fi
    
    if [ -f "docker-compose.prod.yml" ]; then
        echo "Production environment:"
        docker compose -f docker-compose.prod.yml ps 2>/dev/null || echo "  No services running"
        echo
    fi
    
    # Show all GCP IAM Janitor containers
    echo "All GCP IAM Janitor containers:"
    docker ps --filter "ancestor=gcp-iam-janitor" --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" || echo "  No containers running"
}

# Function to clean up containers and images
cleanup() {
    local force=${1:-false}
    
    if [ "$force" != true ]; then
        print_warning "This will remove all GCP IAM Janitor containers and images."
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Cleanup cancelled."
            return
        fi
    fi
    
    print_status "Cleaning up containers and images..."
    
    # Stop and remove containers
    stop_containers
    
    # Remove images
    docker images "gcp-iam-janitor" --format "{{.ID}}" | xargs -r docker rmi -f
    
    # Prune unused volumes and networks
    docker volume prune -f
    docker network prune -f
    
    print_success "Cleanup completed."
}

# Function to run health check
health_check() {
    print_status "Running health check..."
    
    # Check if container is running
    if ! docker ps --filter "ancestor=gcp-iam-janitor" | grep -q "gcp-iam-janitor"; then
        print_error "No GCP IAM Janitor containers are running."
        return 1
    fi
    
    # Check if service is responding
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -f -s "http://localhost:$DEFAULT_PORT/_stcore/health" >/dev/null 2>&1; then
            print_success "Health check passed! Application is responding."
            print_status "Application URL: http://localhost:$DEFAULT_PORT"
            return 0
        fi
        
        ((attempt++))
        print_status "Waiting for application to start... ($attempt/$max_attempts)"
        sleep 2
    done
    
    print_error "Health check failed. Application is not responding after $max_attempts attempts."
    print_status "Check logs with: $0 logs"
    return 1
}

# Function to show usage information
show_usage() {
    cat << EOF
GCP IAM Janitor - Docker Deployment Helper

USAGE:
    $0 <command> [options]

COMMANDS:
    build [version] [--no-cache]     Build Docker image
    run [version] [environment]      Run using Docker Compose (default)
    run-direct [version] [port]      Run container directly with Docker
    stop                             Stop all containers
    logs [--follow]                  Show container logs
    status                           Show container status
    health                           Run health check
    cleanup [--force]                Clean up containers and images
    help                             Show this help message

APP VERSIONS:
    simple                           Basic IAM analysis
    enhanced                         AI-powered insights & advanced analytics
    consolidation                    IAM policy reduction focus
    advanced                         All features (default)

ENVIRONMENTS:
    development                      Local development (default)
    production                       Production deployment

EXAMPLES:
    $0 build                        # Build advanced version
    $0 build simple                 # Build simple version
    $0 run                          # Run advanced version in development
    $0 run enhanced production      # Run enhanced version in production
    $0 run-direct consolidation     # Run consolidation version directly
    $0 logs --follow                # Follow logs in real-time
    $0 health                       # Check if application is healthy
    $0 cleanup                      # Clean up everything

ENVIRONMENT SETUP:
    1. Copy .env.example to .env and configure it
    2. Run: gcloud auth application-default login
    3. Set your GCP_PROJECT_ID in .env file

For more information, see the README.md file.
EOF
}

# Main script logic
main() {
    print_header
    
    case "${1:-}" in
        build)
            check_prerequisites
            build_image "${2:-$DEFAULT_APP_VERSION}" "${3:-false}"
            ;;
        run)
            check_prerequisites
            validate_environment
            run_compose "${2:-$DEFAULT_APP_VERSION}" "${3:-$DEFAULT_ENVIRONMENT}" true
            health_check
            ;;
        run-direct)
            check_prerequisites
            validate_environment
            run_direct "${2:-$DEFAULT_APP_VERSION}" "${3:-$DEFAULT_PORT}"
            ;;
        stop)
            stop_containers
            ;;
        logs)
            local follow=false
            if [ "${2:-}" = "--follow" ] || [ "${2:-}" = "-f" ]; then
                follow=true
            fi
            show_logs "$follow"
            ;;
        status)
            show_status
            ;;
        health)
            health_check
            ;;
        cleanup)
            local force=false
            if [ "${2:-}" = "--force" ]; then
                force=true
            fi
            cleanup "$force"
            ;;
        help|--help|-h)
            show_usage
            ;;
        "")
            print_error "No command specified."
            echo
            show_usage
            exit 1
            ;;
        *)
            print_error "Unknown command: $1"
            echo
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"