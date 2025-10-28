#!/usr/bin/env python3
"""
Quick script to check which view functions referenced in urls.py are missing from views.py
"""
import re
import sys
import os

# Read urls.py
with open('safedriverprogram/driver_program/urls.py', 'r') as f:
    urls_content = f.read()

# Find all views.function_name patterns
view_pattern = r'views\.([a-zA-Z_][a-zA-Z0-9_]*)'
view_functions = re.findall(view_pattern, urls_content)

# Remove duplicates
view_functions = list(set(view_functions))

# Read views.py
with open('safedriverprogram/driver_program/views.py', 'r') as f:
    views_content = f.read()

# Find all function definitions in views.py
def_pattern = r'^def ([a-zA-Z_][a-zA-Z0-9_]*)'
defined_functions = re.findall(def_pattern, views_content, re.MULTILINE)

# Check which ones are missing
missing_functions = []
for func in view_functions:
    if func not in defined_functions:
        missing_functions.append(func)

print("Missing view functions:")
for func in sorted(missing_functions):
    print(f"  - {func}")

print(f"\nTotal missing: {len(missing_functions)}")