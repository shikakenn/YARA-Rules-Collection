import os
import sys
import re

# Default metadata values (excluding 'category' which is set conditionally)
default_fields = {
    "status": "RELEASED",
    "sharing": "TLP:WHITE",
    "source": "YARA-Rules-Collection",
    "author": "Undefined",
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
            inside_meta = False
            meta_start = None
            existing_fields = {}
            category_value = "INFO"

            for i, line in enumerate(lines):
                stripped = line.strip()

                # Start of new rule resets state
                if stripped.startswith("rule "):
                    inside_meta = False
                    existing_fields = {}
                    meta_start = None
                    category_value = "INFO"

                if stripped == "meta:":
                    inside_meta = True
                    meta_start = len(new_lines)
                    new_lines.append(line)
                    continue

                if inside_meta:
                    # If another section starts, meta section ends
                    if stripped.startswith(("strings:", "condition:", "rule ")):
                        inside_meta = False

                        # Determine category value
                        if "malware_type" in existing_fields or "malware_family" in existing_fields:
                            category_value = "MALWARE"
                        else:
                            category_value = "INFO"

                        combined_fields = dict(default_fields)
                        combined_fields["category"] = category_value

                        missing_fields = [
                            f"        {k} = \"{v}\"\n"
                            for k, v in combined_fields.items()
                            if k not in existing_fields
                        ]

                        new_lines[meta_start + 1:meta_start + 1] = missing_fields
                        new_lines.append(line)
                        continue

                    # Remove 'id' line
                    if stripped.startswith("id"):
                        continue

                    # Handle actor_type sanitization
                    if stripped.startswith("actor_type"):
                        parts = stripped.split("=")
                        if len(parts) == 2:
                            actor_val = parts[1].strip().strip('"').lower()
                            if "crime" in actor_val:
                                new_lines.append('        actor_type = "CRIMEWARE"\n')
                            elif "apt" in actor_val:
                                new_lines.append('        actor_type = "APT"\n')
                            continue  # Skip original actor_type line

                    # Fix category if invalid or contains TOOL
                    if stripped.startswith("category"):
                        parts = stripped.split("=")
                        if len(parts) == 2:
                            field_val = parts[1].strip().strip('"').upper()
                            if "TOOL" in field_val:
                                line = '        category = "TOOL"\n'
                            elif field_val not in valid_categories:
                                line = '        category = "INFO"\n'

                    # Capture existing fields
                    if "=" in stripped:
                        parts = stripped.split("=")
                        if len(parts) == 2:
                            field_name = parts[0].strip()
                            field_value = parts[1].strip().strip('"')
                            existing_fields[field_name] = field_value

                    new_lines.append(line)
                    continue

                new_lines.append(line)

            with open(file_path, "w") as f:
                f.writelines(new_lines)

            print(f"✅ Metadata updated in '{file_path}'!")

