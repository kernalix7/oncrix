#!/usr/bin/env python3
"""Check for unsafe blocks without SAFETY comments."""
import os
import re

count = 0
for root, dirs, files in os.walk("crates"):
    for f in files:
        if not f.endswith(".rs"):
            continue
        path = os.path.join(root, f)
        with open(path) as fh:
            lines = fh.readlines()
        for i, line in enumerate(lines):
            if re.search(r"unsafe\s*\{", line):
                has_safety = False
                # Check 6 lines above
                for j in range(1, 7):
                    if i - j >= 0 and "SAFETY" in lines[i - j]:
                        has_safety = True
                        break
                # Check 3 lines below (inside block)
                for j in range(1, 4):
                    if i + j < len(lines) and "SAFETY" in lines[i + j]:
                        has_safety = True
                        break
                # Skip doc comment examples
                if "//!" in line:
                    continue
                if not has_safety:
                    count += 1
                    print(f"{path}:{i+1}: {line.strip()[:80]}")

print(f"\nRemaining unsafe without SAFETY: {count}")
