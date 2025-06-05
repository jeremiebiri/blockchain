#!/bin/bash

echo "Stopping and removing all existing Docker containers and images..."
docker-compose down --rmi all

echo "Building and starting new Docker containers..."
docker-compose up --build

echo "Docker containers started. Check your terminal for logs."
echo "You can now open a new terminal to test the blockchain using curl commands."