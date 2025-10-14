#!/bin/bash

# GCP IAM Janitor - Startup Script

# Choose version based on argument
if [[ $1 == "enhanced" ]]; then
    APP_FILE="app_enhanced.py"
    VERSION="Enhanced (with AI Insights)"
elif [[ $1 == "consolidation" ]]; then
    APP_FILE="app_consolidation.py"
    VERSION="Consolidation Dashboard"
else
    APP_FILE="app_simple.py"
    VERSION="Simple"
fi

echo "🔐 Starting GCP IAM Janitor - $VERSION..."
echo

# Check if we're in the right directory
if [[ ! -f "$APP_FILE" ]]; then
    echo "❌ Error: $APP_FILE not found. Please run this script from the GCP-IAM-Janitor directory."
    exit 1
fi

# Activate virtual environment
if [[ -d ".venv" ]]; then
    echo "📦 Activating virtual environment..."
    source .venv/bin/activate
else
    echo "❌ Error: Virtual environment not found. Please run 'uv sync' first."
    exit 1
fi

# Check for authentication
echo "🔑 Checking authentication..."
python -c "
from google.auth import default
try:
    credentials, project = default()
    print(f'✅ Authenticated! Default project: {project}')
except Exception as e:
    print(f'❌ Authentication failed: {e}')
    print()
    print('Please run: gcloud auth application-default login')
    exit(1)
"

if [[ $? -ne 0 ]]; then
    exit 1
fi

echo
echo "🚀 Starting Streamlit application ($VERSION)..."
echo "📱 The app will open in your browser at: http://localhost:8502"
echo
echo "💡 Usage:"
echo "   ./run.sh              # Run simple version"
echo "   ./run.sh enhanced     # Run enhanced version with AI insights"
echo "   ./run.sh consolidation # Run consolidation dashboard (IAM policy reduction focus)"
echo
echo "Press Ctrl+C to stop the application"
echo

# Run the streamlit app
streamlit run $APP_FILE --server.address localhost --server.port 8502
