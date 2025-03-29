import os
import sys

# Default metadata values
default_fields = {
    "status": "RELEASED",
    "sharing": "TLP:WHITE",
    "source": "YARA-Rules-Collection",
    "author": "Undefined",
    "category": "INFO",
    "description": "NA"
}

valid_categories = {"INFO", "EXPLOIT", "TECHNIQUE", "TOOL", "MALWARE"}

# Check if a directory path is provided
if len(sys.argv) != 2:
    print("Usage: python3 addemeta.py <directory_path>")
    sys.exit(1)

directory_path = sys.argv[1]

if not os.path.isdir(directory_path):
    print(f"Error: Directory '{directory_path}' not found.")
    sys.exit(1)

# Walk through all directories and subdirectories to find .yar and .yara files
for root, _, files in os.walk(directory_path):
    for file_name in files:
        if file_name.endswith(".yar") or file_name.endswith(".yara"):
            file_path = os.path.join(root, file_name)
            
            with open(file_path, "r") as f:
                lines = f.readlines()

            new_lines = []
            meta_section = False
            existing_fields = {}
            meta_index = None
            rules_processed = 0

            for i, line in enumerate(lines):
                stripped_line = line.strip()
                new_lines.append(line)
                
                if stripped_line.startswith("rule "):
                    # Reset tracking for each new rule
                    meta_section = False
                    existing_fields = {}
                    meta_index = None
                    rules_processed += 1

                if "meta:" in stripped_line:
                    meta_section = True
                    meta_index = len(new_lines) - 1  # Track the index to insert missing fields
                    continue
                
                if meta_section:
                    if "}" in stripped_line or stripped_line == "":
                        # Insert missing fields before closing brace
                        missing_fields = [f"        {key} = \"{value}\"\n" for key, value in default_fields.items() if key not in existing_fields]
                        new_lines[meta_index + 1:meta_index + 1] = missing_fields
                        
                        meta_section = False
                    else:
                        parts = stripped_line.split("=")
                        if len(parts) == 2:
                            field_name = parts[0].strip()
                            field_value = parts[1].strip().strip('\"')  # Remove quotes
                            existing_fields[field_name] = field_value

            # Modify category if invalid
            for i in range(len(new_lines)):
                if "category" in new_lines[i]:
                    parts = new_lines[i].strip().split("=")
                    if len(parts) == 2:
                        field_name = parts[0].strip()
                        field_value = parts[1].strip().strip('\"')  # Remove quotes
                        if field_name == "category" and field_value not in valid_categories:
                            new_lines[i] = f"        category = \"INFO\"\n"

            with open(file_path, "w") as f:
                f.writelines(new_lines)

            print(f"Metadata updated in '{file_path}'!")

