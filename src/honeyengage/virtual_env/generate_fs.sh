#!/bin/bash

TARGET_IMAGE="ubuntu:22.04"
GENERATOR_SCRIPT="fs_generator.py"
OUTPUT_FILE="filesystem.json"

echo "===================================="
echo "Generating virtual filesystem from image: $TARGET_IMAGE"
echo "Using generator script: $GENERATOR_SCRIPT"
echo "Output will be saved to: $OUTPUT_FILE"
echo "===================================="

if ! command -v docker &> /dev/null; then
  echo "Docker is not installed. Please install Docker to run this script."
  exit 1
fi

if [ ! -f "$GENERATOR_SCRIPT" ]; then
  echo "Generator script not found: $GENERATOR_SCRIPT"
  exit 1
fi

docker run --rm \
  -v "$(pwd):/app" \
  -w /app \
  $TARGET_IMAGE \
  bash -c "
    echo '  Updating repositories...' &&
    apt-get update -qq &&
    echo '  Installing Python 3...' &&
    apt-get install -y python3 -qq > /dev/null &&
    echo '  Running $GENERATOR_SCRIPT...' &&
    python3 $GENERATOR_SCRIPT
  "

if [ -f "$OUTPUT_FILE" ]; then
  echo "===================================="
  echo "Virtual filesystem generated successfully!"
  echo "Output file: $OUTPUT_FILE"
  echo "===================================="
else
  echo "Error: Output file not found: $OUTPUT_FILE"
  exit 1
fi
