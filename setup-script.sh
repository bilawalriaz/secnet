#!/bin/bash

# Setup script for SecurityScan Pro

echo "Setting up SecurityScan Pro..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Please install Docker before continuing."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose not found. Please install Docker Compose before continuing."
    exit 1
fi

# Create environment file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp backend/env-template.txt .env
    echo "Please edit the .env file and add your Supabase credentials."
    echo "Then run this script again."
    exit 0
fi

# Create Alembic versions directory if it doesn't exist
if [ ! -d backend/app/alembic/versions ]; then
    echo "Creating Alembic versions directory..."
    mkdir -p backend/app/alembic/versions
fi

# Build and start the containers
echo "Building and starting containers..."
docker-compose -f backend/docker-compose.yaml build
docker-compose -f backend/docker-compose.yaml up -d

# Check if the containers are running
if [ $? -eq 0 ]; then
    echo "Setup completed successfully!"
    echo "API is available at: http://localhost:8000"
    echo "API documentation: http://localhost:8000/docs"
else
    echo "Error starting containers. Please check the logs."
    exit 1
fi