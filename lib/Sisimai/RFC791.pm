package Sisimai::RFC791;
use v5.26;
use strict;
use warnings;

sub is_ipv4address {
    # Returns 1 if the argument is an IPv4 address
    # @param    [String] argv1  IPv4 address like "192.0.2.25"
    # @return   [Bool]          1: is an IPv4 address
    # @since v5.2.0
    my $class = shift;
    my $argv0 = shift || return 0;    return 0 if length $argv0  < 7;
    my @octet = split(/[.]/, $argv0); return 0 if scalar @octet != 4;

    for my $e ( @octet ) {
        # Check each octet is between 0 and 255
        return 0 unless $e =~ /\A\d+\z/;
        my $v = int $e;
        return 0 if $v < 0 || $v > 255;
    }
    return 1;
}

sub find {
    # Find an IPv4 address from the given string
    # @param    [String] argv1  String including an IPv4 address
    # @return   [Array]         List of IPv4 addresses
    # @since v5.0.0
    my $class = shift;
    my $argv0 = shift || return undef; return [] if length $argv0 < 7;
    my $ipv4a = [];

    for my $e ( "(", ")", "[", "]", "," ) {
        # Rewrite: "mx.example.jp[192.0.2.1]" => "mx.example.jp 192.0.2.1"
        my $p0 = index($argv0, $e); next if $p0 < 0;
        substr($argv0, $p0, 1, " ");
    }

    IP4A: for my $e ( split(" ", $argv0) ) {
        # Find string including an IPv4 address
        next if index($e, ".") == -1;   # IPv4 address must include "." character

        my $lx = length $e; next if $lx < 7 || $lx > 17; # 0.0.0.0 = 7, [255.255.255.255] = 17
        my $cu = 0;     # Cursor for seeking each octet of an IPv4 address
        my $as = "";    # ASCII Code of each character
        my $eo = "";    # Buffer of each octet of IPv4 Address

        while( $cu < $lx ) {
            # Check whether each character is a number or "." or not
            $as = ord substr($e, $cu++, 1);
            if( $as < 48 || $as > 57 ) {
                # The character is not a number(0-9)
                next IP4A if     $as != 46; # The character is not "."
                next      if     $eo eq ""; # The current buffer is empty
                next IP4A if int $eo > 255; # The current buffer is greater than 255
                $eo = "";
                next;
            }
            $eo .= chr $as;
            next IP4A if int $eo > 255;
        }
        push @$ipv4a, $e;
    }
    return $ipv4a;
}

1;
__END__
=encoding utf-8

=head1 NAME

Sisimai::RFC791 - IP related class

=head1 SYNOPSIS

    use Sisimai::RFC791;

    my $p = Sisimai::RFC791->find("mx7.example.jp:[192.0.2.27]"); # ["192.0.2.27"]

=head1 DESCRIPTION

C<Sisimai::RFC791> is a class related to IP

=head1 CLASS METHODS

=head2 C<B<is_ipv4address(I<String>)>>

C<is_ipv4address> method returns 1 if the argument is an valid IPv4 address.

    print Sisimai::RFC791->is_ipv4address("192.0.2.25");   # 1
    print Sisimai::RFC791->is_ipv4address("123.456.78.9"); # 0

=head2 C<B<find(I<String>)>>

C<find> method return all the IPv4 address found in the given string.

    my $v = "connection refused from 192.0.2.1, DNSBL returned 127.0.0.2";
    my $p = Sisimai::RFC791->find($v); # ["192.0.2.1", "127.0.0.2"]

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2024 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut

