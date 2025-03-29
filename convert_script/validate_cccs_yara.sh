#!/bin/bash

# Check if a directory path is provided
if [ $# -ne 1 ]; then
    echo "Usage: ./run_yara_pipeline.sh <path_to_yara_files>"
    exit 1
fi

YARA_DIR=$1
VALID_DIR="${YARA_DIR}/valid_cccs_yaras"

# Step 1: Run metadata addition
echo "Running metadata addition..."
python3 addmeta.py "$YARA_DIR"

if [ $? -ne 0 ]; then
    echo "Metadata processing failed. Exiting."
    exit 1
fi

# Step 2: Run YARA validation using CCCS validator
echo "Running YARA validation..."
yara_validator -v -r -w -c "$YARA_DIR"

if [ $? -ne 0 ]; then
    echo "Validation failed."
    exit 1
fi

# Step 3: Create a directory for valid YARA files if it doesn't exist
mkdir -p "$VALID_DIR"

# Step 4: Move valid YARA files and rename them
echo "Moving and renaming valid YARA files..."

for file in "$YARA_DIR"/valid_*; do
    if [ -f "$file" ]; then
        new_name=$(echo "$file" | sed 's/^.*\/valid_//')  # Remove "valid_" prefix
        mv "$file" "$VALID_DIR/$new_name"
        echo "Moved: $file → $VALID_DIR/$new_name"
    fi
done

echo "Metadata processing and validation completed successfully!"

