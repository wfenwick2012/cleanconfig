#!/usr/bin/perl
use strict;
use warnings;

# Define rotation key (e.g., "2+,4-,3-,6+")
my @rotation_key = ( ['2', '+'], ['4', '-'], ['3', '-'], ['6', '+'] );

# Function to rotate an octet (8-bit integer)
sub rotate_octet {
    my ($octet, $bits, $direction) = @_;
    
    return $octet if $octet < 0 || $octet > 255;  # Sanity check

    if ($direction eq "+") {
        # Rotate right
        return (($octet >> $bits) | ($octet << (8 - $bits))) & 0xFF;
    } else {
        # Rotate left
        return (($octet << $bits) | ($octet >> (8 - $bits))) & 0xFF;
    }
}

# Function to sanitize IP addresses
sub sanitize_ip {
    my ($ip, $log_fh) = @_;
    my @octets = split(/\./, $ip);

    for my $i (0..3) {
        my ($bits, $direction) = @{$rotation_key[$i]};
        #print $log_fh "Rotating octet $octets[$i] by $bits bits $direction...\n";  # Write to log
        $octets[$i] = rotate_octet($octets[$i], $bits, $direction);
    }

    return join('.', @octets);
}

# Function to sanitize cryptographic text
sub sanitize_cryptotext {
    my ($text, $log_fh) = @_;
    #print $log_fh "Sanitizing cryptotext:     $text...\n";  # Write to log
    # Using a safer way to match hash format
    $text =~ s/(\$9\$\S\S(\S{27})(\S)\S/$1_$2_/;
    return $text;
}

# Function to sanitize SNMP community strings
sub sanitize_snmp {
    my ($line, $log_fh) = @_;
    # print $log_fh "Sanitizing SNMP...\n";  # Write to log
    $line =~ s/(snmp community )([A-Za-z0-9_]+)/$1public/;
    return $line;
}

# Function to sanitize passwords
sub sanitize_password {
    my ($line, $log_fh) = @_;
    # print $log_fh "Sanitizing password...\n";  # Write to log
    $line =~ s/(encrypted-password )(.)(.{10})(..);/$1X$2$3X;/;
    return $line;
}

# Open the log file for writing
open my $log_fh, '>', 'sanitize.log' or die "Cannot open sanitize.log: $!";

# Read from stdin and sanitize line by line
while (my $line = <STDIN>) {
    chomp $line;

    # Sanitize IP addresses
    if ($line =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
        my $ip = $1;
        print $log_fh "Found IP address:        $ip\n";  # Write to log
        my $sanitized_ip = sanitize_ip($ip, $log_fh);
        print $log_fh "IP address sanitized to: $sanitized_ip\n";  # Write to log
        $line =~ s/\Q$ip\E/$sanitized_ip/;
    }

    # Sanitize passwords
    if ($line =~ /(encrypted-password .+)/) {
        print $log_fh "Found encrypted-password field...\n";  # Write to log
        $line = sanitize_password($line, $log_fh);
    }

    # Sanitize cryptographic text (e.g., `$9$` hashes)
    if ($line =~ /(\$9\$\S{1}[A-Za-z0-9\/\.]{29})/) {
        my $cryptotext = $1;
        print $log_fh "Found cryptographic hash:     $cryptotext\n";  # Write to log
        my $sanitized_cryptotext = sanitize_cryptotext($cryptotext, $log_fh);
        print $log_fh "Crypto hash sanitized to:     $sanitized_cryptotext\n";  # Write to log
        $line =~ s/\Q$cryptotext\E/$sanitized_cryptotext/;
    }

    # Sanitize SNMP community strings
    if ($line =~ /(snmp community .+)/) {
        print $log_fh "Found SNMP community string...\n";  # Write to log
        $line = sanitize_snmp($line, $log_fh);
    }

    # Output the sanitized line
    print "$line\n";
}

# Close the log file
close $log_fh;

print "Sanitization complete. Output written to stdout and logs written to sanitize.log.\n";

