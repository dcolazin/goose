# Docker Precompiled Build

This document describes how to build a Docker image for goose using a precompiled binary.

## Base Image
- alpine:3.24.4

## Requirements
1. Use the latest goose precompiled binary
2. Install necessary dependencies (ca-certificates, etc.)
3. Set up proper entrypoint
4. Keep image size minimal

## Build Process
1. Download the latest goose release binary
2. Create Dockerfile
3. Build and test the image