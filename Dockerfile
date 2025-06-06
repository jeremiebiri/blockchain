# Use an official Python runtime as a parent image
FROM python:3.9-slim-buster

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt (if you had any, none so far)
# RUN pip install --no-cache-dir -r requirements.txt

# Expose ports that the nodes will listen on
EXPOSE 5001 5002 5003 5004

# Define environment variable (optional, for future use)
ENV PYTHONUNBUFFERED 1
