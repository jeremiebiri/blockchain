# Dockerfile
# Use a slim Python image
FROM python:3.9-slim-buster

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Expose the ports (for debugging/accessing from host if needed, but not strictly for inter-container)
EXPOSE 5001
EXPOSE 5002

# Command to run node1.py by default (will be overridden by docker-compose)
CMD ["python", "node1.py"]