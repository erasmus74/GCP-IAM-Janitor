#!/bin/bash

# GCP IAM Janitor - Health Check Script
# This script verifies that the GCP IAM Janitor application is running correctly
# and can connect to Google Cloud Platform APIs.

set -e

# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_PORT="8501"
DEFAULT_HOST="localhost"
TIMEOUT=30
MAX_RETRIES=5

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
    echo -e "${PURPLE}===================================${NC}"
    echo -e "${PURPLE} GCP IAM Janitor - Health Check${NC}"
    echo -e "${PURPLE}===================================${NC}"
    echo
}

# Function to check if required tools are available
check_dependencies() {
    print_status "Checking dependencies..."
    
    local missing_deps=()
    
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi
    
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_status "Please install the missing dependencies and try again."
        exit 1
    fi
    
    print_success "All dependencies are available."
}

# Function to check if containers are running
check_containers() {
    print_status "Checking container status..."
    
    # Check for running containers
    local container_count=$(docker ps --filter "ancestor=gcp-iam-janitor" --format "{{.ID}}" | wc -l)
    
    if [ "$container_count" -eq 0 ]; then
        print_error "No GCP IAM Janitor containers are running."
        print_status "Available images:"
        docker images "gcp-iam-janitor" --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedSince}}\t{{.Size}}" || echo "  No images found"
        return 1
    fi
    
    print_success "Found $container_count running container(s)."
    
    # Show container details
    print_status "Container details:"
    docker ps --filter "ancestor=gcp-iam-janitor" --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
    
    return 0
}

# Function to check Streamlit application health
check_streamlit_health() {
    local host=${1:-$DEFAULT_HOST}
    local port=${2:-$DEFAULT_PORT}
    
    print_status "Checking Streamlit application health at $host:$port..."
    
    local url="http://$host:$port/_stcore/health"
    local retry_count=0
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        print_status "Attempt $((retry_count + 1))/$MAX_RETRIES - Testing $url"
        
        # Check if the health endpoint responds
        if curl -f -s --max-time $TIMEOUT "$url" >/dev/null 2>&1; then
            print_success "Streamlit health endpoint is responding."
            
            # Try to get more detailed health info
            local response=$(curl -s --max-time $TIMEOUT "$url" 2>/dev/null || echo "")
            if [ -n "$response" ]; then
                print_status "Health response: $response"
            fi
            
            return 0
        fi
        
        ((retry_count++))
        if [ $retry_count -lt $MAX_RETRIES ]; then
            print_warning "Health check failed, retrying in 5 seconds..."
            sleep 5
        fi
    done
    
    print_error "Streamlit health endpoint is not responding after $MAX_RETRIES attempts."
    return 1
}

# Function to check if the main application page loads
check_app_page() {
    local host=${1:-$DEFAULT_HOST}
    local port=${2:-$DEFAULT_PORT}
    
    print_status "Checking main application page at $host:$port..."
    
    local url="http://$host:$port"
    
    # Check if the main page loads
    if curl -f -s --max-time $TIMEOUT "$url" | grep -q "GCP IAM Janitor" >/dev/null 2>&1; then
        print_success "Main application page is loading correctly."
        return 0
    else
        print_error "Main application page is not loading or doesn't contain expected content."
        
        # Try to get response headers for debugging
        print_status "Response headers:"
        curl -I -s --max-time $TIMEOUT "$url" 2>/dev/null || echo "  Failed to get headers"
        
        return 1
    fi
}

# Function to check GCP connectivity (if possible)
check_gcp_connectivity() {
    print_status "Checking GCP connectivity from container..."
    
    # Find a running container
    local container_id=$(docker ps --filter "ancestor=gcp-iam-janitor" --format "{{.ID}}" | head -n 1)
    
    if [ -z "$container_id" ]; then
        print_error "No running container found for GCP connectivity test."
        return 1
    fi
    
    # Check if gcloud is available in container and can authenticate
    print_status "Testing Google Cloud authentication in container $container_id..."
    
    # Try to list projects as a connectivity test
    if docker exec "$container_id" python -c "
import os
try:
    from google.auth import default
    credentials, project = default()
    print(f'✅ Authentication successful! Default project: {project}')
    
    # Try to import required modules
    from google.cloud import resourcemanager_v3
    print('✅ Google Cloud Resource Manager client available')
    
    from google.cloud import iam_v1
    print('✅ Google Cloud IAM client available')
    
    print('✅ All required Google Cloud libraries are working')
except Exception as e:
    print(f'❌ GCP connectivity issue: {e}')
    exit(1)
" 2>/dev/null; then
        print_success "GCP connectivity test passed."
        return 0
    else
        print_warning "GCP connectivity test failed."
        print_status "This may be due to missing credentials or network issues."
        print_status "Ensure you have run 'gcloud auth application-default login'"
        print_status "or configured service account credentials properly."
        return 1
    fi
}

# Function to perform network connectivity tests
check_network() {
    local host=${1:-$DEFAULT_HOST}
    local port=${2:-$DEFAULT_PORT}
    
    print_status "Checking network connectivity to $host:$port..."
    
    # Check if port is open
    if command -v nc &> /dev/null; then
        if nc -z "$host" "$port" 2>/dev/null; then
            print_success "Port $port is open and accepting connections."
        else
            print_error "Port $port is not accepting connections."
            return 1
        fi
    elif command -v telnet &> /dev/null; then
        if echo "quit" | telnet "$host" "$port" 2>/dev/null | grep -q "Connected"; then
            print_success "Port $port is open and accepting connections."
        else
            print_error "Port $port is not accepting connections."
            return 1
        fi
    else
        print_warning "Neither 'nc' nor 'telnet' is available for port testing."
        print_status "Skipping direct port connectivity test."
    fi
    
    return 0
}

# Function to check container logs for errors
check_logs() {
    print_status "Checking container logs for errors..."
    
    local container_id=$(docker ps --filter "ancestor=gcp-iam-janitor" --format "{{.ID}}" | head -n 1)
    
    if [ -z "$container_id" ]; then
        print_error "No running container found for log analysis."
        return 1
    fi
    
    # Check recent logs for errors
    local error_count=$(docker logs --tail 100 "$container_id" 2>&1 | grep -i -E "(error|exception|failed|traceback)" | wc -l)
    
    if [ "$error_count" -eq 0 ]; then
        print_success "No errors found in recent container logs."
    else
        print_warning "Found $error_count potential error(s) in recent logs."
        print_status "Recent errors/warnings:"
        docker logs --tail 50 "$container_id" 2>&1 | grep -i -E "(error|exception|failed|warning)" | tail -5 || echo "  None found in tail"
    fi
    
    # Check if application started successfully
    if docker logs --tail 50 "$container_id" 2>&1 | grep -q "Starting Streamlit\|streamlit run\|You can now view"; then
        print_success "Streamlit appears to have started successfully."
    else
        print_warning "Streamlit startup messages not found in logs."
    fi
    
    return 0
}

# Function to generate health report
generate_report() {
    local host=${1:-$DEFAULT_HOST}
    local port=${2:-$DEFAULT_PORT}
    local overall_status="HEALTHY"
    
    echo
    print_status "=== HEALTH CHECK REPORT ==="
    echo
    
    # Container status
    if check_containers; then
        echo "✅ Containers: RUNNING"
    else
        echo "❌ Containers: NOT RUNNING"
        overall_status="UNHEALTHY"
    fi
    
    # Network connectivity
    if check_network "$host" "$port"; then
        echo "✅ Network: ACCESSIBLE"
    else
        echo "❌ Network: INACCESSIBLE"
        overall_status="UNHEALTHY"
    fi
    
    # Streamlit health
    if check_streamlit_health "$host" "$port"; then
        echo "✅ Streamlit: HEALTHY"
    else
        echo "❌ Streamlit: UNHEALTHY"
        overall_status="UNHEALTHY"
    fi
    
    # Application page
    if check_app_page "$host" "$port"; then
        echo "✅ Application: LOADING"
    else
        echo "❌ Application: NOT LOADING"
        overall_status="UNHEALTHY"
    fi
    
    # GCP connectivity
    if check_gcp_connectivity; then
        echo "✅ GCP Connectivity: WORKING"
    else
        echo "⚠️  GCP Connectivity: ISSUES DETECTED"
        # Don't mark as unhealthy since this might be expected in some environments
    fi
    
    echo
    if [ "$overall_status" = "HEALTHY" ]; then
        print_success "=== OVERALL STATUS: HEALTHY ==="
        print_status "Application URL: http://$host:$port"
        echo
        return 0
    else
        print_error "=== OVERALL STATUS: UNHEALTHY ==="
        print_status "Please check the issues above and review container logs."
        echo
        return 1
    fi
}

# Function to show usage information
show_usage() {
    cat << EOF
GCP IAM Janitor - Health Check Script

USAGE:
    $0 [options]

OPTIONS:
    --host HOST         Hostname to check (default: $DEFAULT_HOST)
    --port PORT         Port to check (default: $DEFAULT_PORT)
    --timeout SECONDS   Request timeout (default: $TIMEOUT)
    --retries COUNT     Maximum retries (default: $MAX_RETRIES)
    --containers-only   Only check container status
    --network-only      Only check network connectivity
    --streamlit-only    Only check Streamlit health
    --gcp-only         Only check GCP connectivity
    --help             Show this help message

EXAMPLES:
    $0                          # Full health check
    $0 --host example.com --port 8080  # Check remote instance
    $0 --containers-only       # Check only container status
    $0 --timeout 60            # Use 60 second timeout

RETURN CODES:
    0    All checks passed
    1    Some checks failed
    2    Critical error (no containers, etc.)

EOF
}

# Main script logic
main() {
    print_header
    
    # Parse command line arguments
    local host="$DEFAULT_HOST"
    local port="$DEFAULT_PORT"
    local check_mode="full"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --host)
                host="$2"
                shift 2
                ;;
            --port)
                port="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --retries)
                MAX_RETRIES="$2"
                shift 2
                ;;
            --containers-only)
                check_mode="containers"
                shift
                ;;
            --network-only)
                check_mode="network"
                shift
                ;;
            --streamlit-only)
                check_mode="streamlit"
                shift
                ;;
            --gcp-only)
                check_mode="gcp"
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    check_dependencies
    
    case "$check_mode" in
        containers)
            check_containers
            ;;
        network)
            check_network "$host" "$port"
            ;;
        streamlit)
            check_streamlit_health "$host" "$port"
            ;;
        gcp)
            check_gcp_connectivity
            ;;
        full|*)
            generate_report "$host" "$port"
            ;;
    esac
}

# Run main function with all arguments
main "$@"