#!/usr/bin/env python3
import sys
import os
import re
import argparse
from pathlib import Path

"""
clean6.py
Removes sensitive (sanitize) information from Juniper router configuration files
(c)2025 wynn.fenwick@telus.com
TELUS CONFIDENTIAL
"""

# Define rotation key (e.g., "2+,4-,3-,6+")
ROTATION_KEY = [('2', '+'), ('4', '-'), ('3', '-'), ('6', '+')]

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Removes sensitive (sanitize) information from Juniper router configuration files.')
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
    """Sanitize SNMP community strings"""
    return re.sub(r'community "(\S+)" \{', 'community "OBFUSCATED" {', line)

def sanitize_password(line, log_fh):
    """Sanitize passwords and hashes"""
    patterns = [
        (r'(^\s+authentication-key "\$1\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'(^\s+encrypted-password "\$1\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'(^\s+secret "\$1\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'(^\s+authentication-key "\$9\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
        (r'(^\s+secret "\$9\$)(..)([^;]+)(..)(\";.*)', r'\1XX\3XX\5'),
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
        
        # Sanitize passwords and hashes
        if re.search(r'encrypted-password|(\$[19]\$)', line):
            line = sanitize_password(line, log_fh)
            print(f"Obfuscating password/hash field {line.lstrip()} ...", file=log_fh)
            line = line.replace("## SECRET-DATA", "## SECRET-DATA-OBFUSCATED")
        
        # Sanitize SNMP community strings
        if re.search(r'(community .+)', line):
            print("Found SNMP community string...", file=log_fh)
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
        input_dir = Path('.') / 'CSR' / 'CSR' / 'in-situ-configs'
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