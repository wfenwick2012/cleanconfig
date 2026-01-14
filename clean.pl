#!/usr/bin/perl
use strict;
use warnings;
use File::Spec;
use File::Basename;

# Directory containing the router configurations
my $input_dir = File::Spec->catdir('..', 'CSR', 'CSR', 'in-situ-configs');
my $output_dir = 'sanitized_configs';

# Create output directory if it doesn't exist
mkdir $output_dir unless -d $output_dir;

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
        $octets[$i] = rotate_octet($octets[$i], $bits, $direction);
    }

    return join('.', @octets);
}

# Function to sanitize cryptographic text
sub sanitize_cryptotext {
    my ($text, $log_fh) = @_;
    # Fixed the regex here
    $text =~ s/(\$9\$\S\S)(\S{27})(\S)\S/$1$2_$3_/;
    return $text;
}

# Function to sanitize SNMP community strings
sub sanitize_snmp {
    my ($line, $log_fh) = @_;
    $line =~ s/(snmp community )([A-Za-z0-9_]+)/$1public/;
    return $line;
}

# Function to sanitize passwords
sub sanitize_password {
    my ($line, $log_fh) = @_;
    $line =~ s/(encrypted-password )(.)(.{10})(..);/$1X$2$3X;/;
    return $line;
}

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

    while (my $line = <$in_fh>) {
        chomp $line;

        # Sanitize IP addresses
        if ($line =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
            my $ip = $1;
            print $log_fh "Found IP address:        $ip\n";
            my $sanitized_ip = sanitize_ip($ip, $log_fh);
            print $log_fh "IP address sanitized to: $sanitized_ip\n";
            $line =~ s/\Q$ip\E/$sanitized_ip/g;
        }

        # Sanitize passwords
        if ($line =~ /(encrypted-password .+)/) {
            print $log_fh "Found encrypted-password field...\n";
            $line = sanitize_password($line, $log_fh);
        }

        # Sanitize cryptographic text (e.g., `$9$` hashes)
        if ($line =~ /(\$9\$\S{1}[A-Za-z0-9\/\.]{29})/) {
            my $cryptotext = $1;
            print $log_fh "Found cryptographic hash:     $cryptotext\n";
            my $sanitized_cryptotext = sanitize_cryptotext($cryptotext, $log_fh);
            print $log_fh "Crypto hash sanitized to:     $sanitized_cryptotext\n";
            $line =~ s/\Q$cryptotext\E/$sanitized_cryptotext/g;
        }

        # Sanitize SNMP community strings
        if ($line =~ /(snmp community .+)/) {
            print $log_fh "Found SNMP community string...\n";
            $line = sanitize_snmp($line, $log_fh);
        }

        # Output the sanitized line
        print $out_fh "$line\n";
    }

    close $in_fh;
    close $out_fh;
    close $log_fh;

    print "Processed $filename. Sanitized output written to $output_file and logs written to $log_file.\n";
}
closedir($dh);

print "All files processed. Sanitized configs are in the '$output_dir' directory.\n";