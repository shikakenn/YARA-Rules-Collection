#!/bin/bash

# Check if a directory path is provided
if [ $# -ne 1 ]; then
    echo "Usage: ./validate_cccs_yara.sh <path_to_yara_files>"
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
    echo "Validation completed with some errors. Continuing to process valid rules..."
else
    echo "Validation completed successfully."
fi

# Step 3: Create a directory for valid YARA files
mkdir -p "$VALID_DIR"

# Step 4: Move valid YARA files and preserve folder structure
echo "Moving and renaming valid YARA files (preserving folder structure)..."

find "$YARA_DIR" -type f -name "valid_*" | while read -r file; do
    # Get relative path from YARA_DIR and remove "valid_" prefix from filename
    relative_path="${file#$YARA_DIR/}"
    dir_path=$(dirname "$relative_path")
    filename=$(basename "$relative_path")
    new_name="${filename#valid_}"

    # Create the same subfolder path inside VALID_DIR
    mkdir -p "$VALID_DIR/$dir_path"

    # Move the file to its new location
    mv "$file" "$VALID_DIR/$dir_path/$new_name"
done

echo "Metadata processing and validation pipeline completed."

