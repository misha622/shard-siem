#!/bin/bash
# SHARD Enterprise — Production Deployment Script
set -e

echo "🚀 Deploying SHARD Enterprise to Production..."

# Load env
if [ -f .env ]; then
    export $(cat .env | xargs)
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Installing..."
    curl -fsSL https://get.docker.com | sh
fi

# Check NVIDIA Docker for GPU
if [ "${SHARD_USE_GPU:-false}" = "true" ]; then
    if ! docker run --rm --gpus all nvidia/cuda:12.1-base nvidia-smi &> /dev/null; then
        echo "❌ NVIDIA Docker not configured. Install nvidia-container-toolkit."
        exit 1
    fi
    echo "✅ GPU support detected"
fi

# Build image
echo "📦 Building SHARD Enterprise image..."
docker build -t shard-enterprise:latest -f Dockerfile .

# Deploy cluster
echo "🌐 Starting production cluster..."
docker compose -f docker-compose.production.yml up -d

# Wait for healthy
echo "⏳ Waiting for services..."
sleep 10

# Health check
if curl -sf http://localhost:8080/api/health > /dev/null; then
    echo "✅ SHARD Enterprise is running!"
    echo "📊 Dashboard: http://localhost:8080"
    echo "📈 Metrics: http://localhost:9090"
else
    echo "❌ Health check failed. Check logs:"
    docker compose -f docker-compose.production.yml logs --tail=50
fi
