#!/usr/bin/env python3
"""
Script to fix let-chain syntax issues for stable Rust compatibility.
Converts unstable let-chain patterns to nested if-let statements.
"""

import re
import os
import sys
from pathlib import Path

def fix_let_chains_in_file(filepath):
    """Fix let-chain patterns in a single file."""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Pattern 1: if condition && let Some(x) = expr
    pattern1 = r'(\s*)if\s+([^&\n]+?)\s*&&\s*let\s+([^=]+?)\s*=\s*([^{]+?)\s*\{'
    def replace1(match):
        indent = match.group(1)
        condition = match.group(2).strip()
        let_pattern = match.group(3).strip()
        expr = match.group(4).strip()
        return f'{indent}if {condition} {{\n{indent}    if let {let_pattern} = {expr} {{'
    
    # Pattern 2: if let Some(x) = expr && condition
    pattern2 = r'(\s*)if\s+let\s+([^=]+?)\s*=\s*([^&]+?)\s*&&\s*([^{]+?)\s*\{'
    def replace2(match):
        indent = match.group(1)
        let_pattern = match.group(2).strip()
        expr = match.group(3).strip()
        condition = match.group(4).strip()
        return f'{indent}if let {let_pattern} = {expr} {{\n{indent}    if {condition} {{'
    
    # Pattern 3: && let Some(x) = expr (continuation)
    pattern3 = r'(\s*)&&\s*let\s+([^=]+?)\s*=\s*([^&\n{]+?)(?=\s*(?:&&|\{|\n))'
    def replace3(match):
        indent = match.group(1)
        let_pattern = match.group(2).strip()
        expr = match.group(3).strip()
        # This needs context-aware replacement
        return f' {{\n{indent}    if let {let_pattern} = {expr}'
    
    # Apply replacements
    content = re.sub(pattern1, replace1, content)
    content = re.sub(pattern2, replace2, content)
    
    # Handle complex nested patterns
    # Pattern: if let Some(x) = foo && let Some(y) = bar
    pattern4 = r'(\s*)if\s+let\s+([^=]+?)\s*=\s*([^&]+?)\n?\s*&&\s*let\s+([^=]+?)\s*=\s*([^{]+?)\s*\{'
    def replace4(match):
        indent = match.group(1)
        let_pattern1 = match.group(2).strip()
        expr1 = match.group(3).strip()
        let_pattern2 = match.group(4).strip()
        expr2 = match.group(5).strip()
        return f'{indent}if let {let_pattern1} = {expr1} {{\n{indent}    if let {let_pattern2} = {expr2} {{'
    
    content = re.sub(pattern4, replace4, content)
    
    # Fix closing braces for nested if-lets
    # Count the number of new nested ifs we created
    if content != original_content:
        # Add closing braces where needed
        lines = content.split('\n')
        fixed_lines = []
        brace_stack = []
        
        for i, line in enumerate(lines):
            fixed_lines.append(line)
            
            # Track opening braces from our conversions
            if 'if let' in line and '{' in line:
                # Check if this was part of our conversion
                if i > 0 and 'if' in lines[i-1] and '{' in lines[i-1]:
                    brace_stack.append(len(line) - len(line.lstrip()))
            
            # Add closing brace when indentation decreases
            if brace_stack and i < len(lines) - 1:
                current_indent = len(line) - len(line.lstrip())
                next_indent = len(lines[i+1]) - len(lines[i+1].lstrip())
                
                while brace_stack and next_indent <= brace_stack[-1]:
                    indent_level = brace_stack.pop()
                    fixed_lines.append(' ' * indent_level + '}')
        
        content = '\n'.join(fixed_lines)
    
    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    # List of files with let-chain issues
    files = [
        'src/identity/node_identity_extensions.rs',
        'src/security.rs',
        'src/config.rs',
        'src/dht/network_integration.rs',
        'src/dht/latency_aware_selection.rs',
        'src/dht/skademlia.rs',
        'src/dht/optimized_storage.rs',
        'src/transport.rs',
        'src/quantum_crypto/mod.rs',
        'src/secure_memory.rs',
        'src/messaging/reactions.rs',
        'src/messaging/search.rs',
        'src/messaging/composer.rs',
        'src/messaging/encryption.rs',
        'src/messaging/webrtc/signaling.rs',
        'src/messaging/webrtc/media.rs',
        'src/adaptive/churn_prediction.rs',
        'src/adaptive/learning.rs',
        'src/adaptive/performance.rs',
        'src/adaptive/multi_armed_bandit.rs',
        'src/mcp.rs',
    ]
    
    project_root = Path('/Users/davidirvine/Desktop/Devel/projects/saorsa-core')
    
    fixed_count = 0
    for file_path in files:
        full_path = project_root / file_path
        if full_path.exists():
            if fix_let_chains_in_file(full_path):
                print(f"Fixed: {file_path}")
                fixed_count += 1
        else:
            print(f"File not found: {file_path}")
    
    print(f"\nFixed {fixed_count} files")

if __name__ == '__main__':
    main()