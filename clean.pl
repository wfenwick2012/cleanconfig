#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Basename;
use Getopt::Std;
#
# clean6.pl
# Removes sensitive (sanitize) information from Juniper router configuration files
# runs in Cygwin for Windows (Perl 5 interpreter)
# (c)2025 wynn.fenwick@telus.com
# TELUS CONFIDENTIAL
#
our ($opt_m, $opt_a, $opt_h);
getopts('mah');

# New function to display usage information
sub display_usage {
    print "$0 removes sensitive (sanitize) information from Juniper router configuration files.\n";
    print "Usage: $0 [options] < input_file > output_file\n";
    print "   or: $0 [options] (for directory processing)\n\n";
    print "Options:\n";
    print "  -m    Skip more prompts\n";
    print "  -a    Rotate IP addresses (default: no rotation)\n";
    print "  -h    Display this help message\n";
}

# Check if -h option is used, if so, display usage and exit
if ($opt_h) {
    display_usage();
    exit 0;
}

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

    if ($opt_a) {
        for my $i (0..3) {
            my ($bits, $direction) = @{$rotation_key[$i]};
            $octets[$i] = rotate_octet($octets[$i], $bits, $direction);
        }
    }

    return join('.', @octets);
}

# Function to sanitize SNMP community strings
sub sanitize_snmp {
    my ($line, $log_fh) = @_;
    $line =~ s/community \"(\S+)\" \{/community \"OBFUSCATED\" {/;
    return $line;
}

# Function to sanitize passwords and hashes
sub sanitize_password {
    my ($line, $log_fh) = @_;
    
    # Handle $1$ MD5 hashes
    if ($line =~ /(^\s+authentication-key \"\$1\$)(..)([^;]+)(..)(\";.*)/) {
        return $1 . "XX". $3. "XX" . $5;
    }

    elsif ($line =~ /(^\s+encrypted-password \"\$1\$)(..)([^;]+)(..)(\";.*)/) {
        return $1 . "XX". $3. "XX" . $5;
    }

    elsif ($line =~ /(^\s+secret \"\$1\$)(..)([^;]+)(..)(\";.*)/) {
        return $1 . "XX". $3. "XX" . $5;
    }

    elsif ($line =~ /(^\s+authentication-key \"\$9\$)(..)([^;]+)(..)(\";.*)/) {
        return $1 . "XX". $3. "XX" . $5;
    }

    elsif ($line =~ /(^\s+secret \"\$9\$)(..)([^;]+)(..)(\";.*)/) {
        return $1 . "XX". $3. "XX" . $5;
    }

    # Handle simple encrypted passwords
    elsif ($line =~ /(encrypted-password\s+)(..)([^;]+)(..)(;.*)/) {
        return $1 . "XX". $3. "XX" . $5;
    }
    
    return $line;
}

# Function to process a single input stream
sub process_input {
    my ($in_fh, $out_fh, $log_fh) = @_;

    while (my $line = <$in_fh>) {
        # Skip more prompts if -m option is set
        next if ($opt_m && $line =~ /---\(more( \d{1,2}%)?\)---/);
        
        chomp $line;

        # Sanitize IP addresses
        if ($line =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
            my $ip = $1;
            print $log_fh "Found IP address:        $ip\n";
            my $sanitized_ip = sanitize_ip($ip, $log_fh);
            print $log_fh "IP address sanitized to: $sanitized_ip\n";
            $line =~ s/\Q$ip\E/$sanitized_ip/g;
        }

        # Sanitize passwords and hashes
        if ($line =~ /encrypted-password|(\$[19]\$)/) {
            $line = sanitize_password($line, $log_fh);
            print $log_fh "Obfuscating password/hash field " . ($line =~ s/^\s+//r) . " ...\n";
            $line =~ s/\#\# SECRET-DATA/\#\# SECRET-DATA-OBFUSCATED/g;
        }

        # Sanitize SNMP community strings
        if ($line =~ /(community .+)/) {
            print $log_fh "Found SNMP community string...\n";
            $line = sanitize_snmp($line, $log_fh);
        }

        # Output the sanitized line
        print $out_fh "$line\n" if $line =~ /\S/; # Only print lines with non-whitespace characters
    }
}

# Check if we're receiving input from stdin
if (-p STDIN || ! -t STDIN) {  # Detects both pipe and file redirection
    # Processing from stdin
    open my $log_fh, '>', 'sanitize.log' or die "Cannot open sanitize.log: $!";
    process_input(\*STDIN, \*STDOUT, $log_fh);
    close $log_fh;
    print STDERR "Sanitization complete. Logs written to sanitize.log.\n";
}
else {
    # Processing directory
    my $input_dir = File::Spec->catdir('.', 'CSR', 'CSR', 'in-situ-configs');
    my $output_dir = 'sanitized_configs';

    # Create output directory if it doesn't exist
    mkdir $output_dir unless -d $output_dir;

    # Process each file in the input directory
    opendir(my $dh, $input_dir) || die "Can't open $input_dir: $!";
    while (my $filename = readdir($dh)) {
        next if $filename =~ /^\./;  # Skip hidden files and directories

        my $input_file = File::Spec->catfile($input_dir, $filename);
        my $output_file = File::Spec->catfile($output_dir, "sanitized_$filename");
        my $log_file = File::Spec->catfile($output_dir, "log_$filename.log");

        open my $in_fh, '<', $input_file or die "Cannot open $input_file: $!";
        open my $out_fh, '>', $output_file or die "Cannot open $output_file: $!";
        open my $log_fh, '>', $log_file or die "Cannot open $log_file: $!";

        process_input($in_fh, $out_fh, $log_fh);

        close $in_fh;
        close $out_fh;
        close $log_fh;

        print "Processed $filename. Sanitized output written to $output_file and logs written to $log_file.\n";
    }
    closedir($dh);

    print "All files processed. Sanitized configs are in the '$output_dir' directory.\n";
}