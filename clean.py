#!/usr/bin/env python3
import sys
import os
import re
import argparse
from pathlib import Path

"""
clean9.py
Sanitizes information from Juniper router configuration piped on stdin, else reads files from ./in_situ_configs/
(c)2025 wynn.fenwick@telus.com
TELUS CONFIDENTIAL
"""

# Define rotation key (e.g., "2+,4-,3-,6+")
ROTATION_KEY = [('2', '+'), ('4', '-'), ('3', '-'), ('6', '+')]

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Sanitizes information from Juniper router configuration piped on stdin, else reads files from ./in_situ_configs/',
        # Add an epilog to explain the operating modes
        epilog="""
Usage Modes:
  1. Piped Input (stdin/stdout):
     Reads configuration data from stdin.
     Writes sanitized configuration to stdout.
     Writes log information to 'sanitize.log' in the current directory.
     Example: cat my_config.txt | ./%(prog)s -a

  2. Directory Mode (default):
     If no input is piped via stdin, the script runs in directory mode.
     This mode (which is what you asked about as the 'first argument' behavior)
     is the default action when run without piped input.
     Reads files from: ./in_situ_configs/
     Writes sanitized files to: ./sanitized_configs/
     Writes log files to: ./sanitized_configs/
""",
        # Use RawDescriptionHelpFormatter to preserve newlines in the epilog
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-m', action='store_true', help='Skip more prompts')
    parser.add_argument('-a', action='store_true', help='Rotate IP addresses (default: no rotation)')
    return parser.parse_args()


def rotate_octet(octet, bits, direction):
    """Rotate an octet (8-bit integer)"""
    try:
        octet = int(octet)
        if not 0 <= octet <= 255:
            return octet
        
        bits = int(bits)
        if direction == "+":
            # Rotate right
            return ((octet >> bits) | (octet << (8 - bits))) & 0xFF
        else:
            # Rotate left
            return ((octet << bits) | (octet >> (8 - bits))) & 0xFF
    except ValueError:
        return octet

def sanitize_ip(ip, args, log_fh):
    """Sanitize IP addresses"""
    octets = ip.split('.')
    
    if args.a:
        for i in range(4):
            bits, direction = ROTATION_KEY[i]
            octets[i] = str(rotate_octet(octets[i], bits, direction))
    
    return '.'.join(octets)

def sanitize_snmp(line, log_fh):
    """
    Sanitize SNMP community strings, handling both quoted and unquoted strings,
    and preserving context for strings longer than 4 characters.
    """
    
    # Pattern groups:
    # 1: (community ) - The literal "community " prefix
    # 2: (")?           - An optional opening quote
    # 3: (\S+)          - The community string content
    # 4: (\2)           - Matches the same as group 2 (the optional quote)
    # 5: ( \{)          - The literal " {" suffix
    pattern = r'(community )("?)(\S+)(\2)( \{)'

    def replacer(match):
        # Extract the captured parts
        prefix  = match.group(1)  # 'community '
        quote1  = match.group(2)  # '"' or ''
        content = match.group(3)  # 'my-secret-string'
        quote2  = match.group(4)  # '"' or ''
        suffix  = match.group(5)  # ' {'

        # Use Python logic to decide how to obfuscate
        if len(content) <= 4:
            # String is too short, apply "first 1, XXX" logic
            first_two = content[:1]
            obfuscated_content = f"{first_two}XXX"
            
        else:
            # Apply "first 2, last 2" logic
            first_two = content[:2]
            last_two  = content[-2:]
            obfuscated_content = f"{first_two}XXX{last_two}"
            
        # Rebuild the line
        return f"{prefix}{quote1}{obfuscated_content}{quote2}{suffix}"

    return re.sub(pattern, replacer, line)


def sanitize_ssh_pub_key(line, log_fh):
    """Sanitize ssh public key"""
    
    # Pattern:
    # Group 1: (^\s+ssh-rsa\s+"ssh-rsa\s+) - The prefix
    # Group 2: (\S+)                       - The entire base64 key
    # Group 3: (.*)                       - The optional comment (e.g., " jenkins@...")
    # Group 4: (";)                       - The closing quote and semicolon
    pattern = r'(^\s+ssh-rsa\s+"ssh-rsa\s+)(\S+)(.*)(";)'

    def replacer(match):
        prefix  = match.group(1)
        key     = match.group(2)
        comment = match.group(3) # Will be ' jenkins@...' or ''
        suffix  = match.group(4)

        # Apply Python slicing to the key
        if len(key) > 20: # Make sure key is reasonably long
            first_part = key[:10]  # First 10 chars
            last_part  = key[-10:] # Last 10 chars
            obfuscated_key = f"{first_part}XXX...XXX{last_part}"
        else:
            obfuscated_key = "OBFUSCATED" # Key is too short, just hide it
        
        print(f"Obfuscating SSH public key...", file=log_fh)
        
        # Rebuild the line, adding our own obfuscation comment
        return f"{prefix}{obfuscated_key}{comment}{suffix} ## SSH-PUBLIC-KEY-OBFUSCATED"

    # Check if the line matches before doing anything
    if re.search(pattern, line):
        # Run the replacement
        line = re.sub(pattern, replacer, line)
        # Remove the original "## SECRET-DATA" tag if it exists
        line = line.replace("## SECRET-DATA", "")
        return line
        
    return line

def sanitize_password(line, log_fh):
    """Sanitize passwords and hashes"""
    patterns = [
        (r'(^\s+authentication-key "\$1\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'(^\s+encrypted-password "\$1\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'(^\s+secret "\$1\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'(^\s+authentication-key "\$9\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'(^\s+secret "\$9\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'( secret "\$9\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'(encrypted-password\s+)(..)([^;]+)(..)(;.*)', r'\1XX\3XX\5')
    ]
    
    for pattern, replacement in patterns:
        if re.search(pattern, line):
            return re.sub(pattern, replacement, line)
    
    return line

def process_input(in_fh, out_fh, log_fh, args):
    """Process a single input stream"""
    for line in in_fh:
        # Skip more prompts if -m option is set
        if args.m and re.search(r'---\(more( \d{1,2}%)?\)---', line):
            continue
            
        line = line.rstrip()
        
        # Sanitize IP addresses
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if ip_match:
            ip = ip_match.group(1)
            print(f"Found IP address:        {ip}", file=log_fh)
            sanitized_ip = sanitize_ip(ip, args, log_fh)
            print(f"IP address sanitized to: {sanitized_ip}", file=log_fh)
            line = line.replace(ip, sanitized_ip)
            
        #sanitize SSH public keys (paranoid yes)
        if "ssh-rsa" in line:
            print("Found SSH public key string...", file=log_fh)
            line = sanitize_ssh_pub_key(line, log_fh)         
        
        # Sanitize passwords and hashes
        if re.search(r'encrypted-password|(\$[19]\$)', line):
            line = sanitize_password(line, log_fh)
            print(f"Obfuscating password/hash field {line.lstrip()} ...", file=log_fh)
            line = line.replace("## SECRET-DATA", "## SECRET-DATA-OBFUSCATED")
        
        # Sanitize SNMP community strings
        if re.search(r'(community .+)', line):
            print("Found SNMP community string...", file=log_fh)
            line = sanitize_snmp(line, log_fh)
 
        if re.search(r'(trap-group .+)', line):
            print("Found SNMP trap community string...", file=log_fh)
            line = sanitize_snmp(line, log_fh)
         
        # Output the sanitized line
        if re.search(r'\S', line):  # Only print lines with non-whitespace characters
            print(line, file=out_fh)

def main():
    args = parse_arguments()
    
    # Check if we're receiving input from stdin
    if not sys.stdin.isatty():
        # Processing from stdin
        with open('sanitize.log', 'w') as log_fh:
            process_input(sys.stdin, sys.stdout, log_fh, args)
        print("Sanitization complete. Logs written to sanitize.log.", file=sys.stderr)
    else:
        # Processing directory
        input_dir = Path('.') / 'in_situ_configs'
        output_dir = Path('sanitized_configs')
        
        # Create output directory if it doesn't exist
        output_dir.mkdir(exist_ok=True)
        
        # Process each file in the input directory
        for input_file in input_dir.glob('*'):
            if input_file.name.startswith('.'):
                continue
                
            output_file = output_dir / f"sanitized_{input_file.name}"
            log_file = output_dir / f"log_{input_file.name}.log"
            
            with open(input_file, 'r') as in_fh, \
                 open(output_file, 'w') as out_fh, \
                 open(log_file, 'w') as log_fh:
                process_input(in_fh, out_fh, log_fh, args)
                
            print(f"Processed {input_file.name}. Sanitized output written to {output_file} "
                  f"and logs written to {log_file}")
        
        print(f"All files processed. Sanitized configs are in the '{output_dir}' directory.")

if __name__ == '__main__':
    main()