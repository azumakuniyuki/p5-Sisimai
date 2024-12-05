package Sisimai::RFC1123;
use v5.26;
use strict;
use warnings;

sub is_internethost {
    # Check that the argument is a valid Internet hostname or not
    # @param    [String] argv0  String to be checked
    # @return   [Boolean]       0: is not a valid hostname
    #                           1: is a valid hostname
    # @since v5.2.0
    my $class = shift;
    my $argv0 = shift || return 0;

    return 0 if length $argv0 > 255;
    return 0 if length $argv0 <   4;
    return 0 if index($argv0, ".") == -1;
    return 0 if index($argv0, "..") > -1;
    return 0 if index($argv0, "--") > -1;
    return 0 if index($argv0, ".") ==  0;
    return 0 if index($argv0, "-") ==  0;
    return 0 if substr($argv0, -1, 1) eq "-";

    my $valid = 1;
    my $token = [split(/\./, $argv0)] || ['0'];

    my $hostnameok = 1;
    my @characters = split("", uc $argv0);
    for my $e ( @characters ) {
        # Check each characater is a number or an alphabet
        my $f = ord $e;
        if( $f  < 45            ) { $hostnameok = 0; last } # 45 = '-'
        if( $f == 47            ) { $hostnameok = 0; last } # 47 = '/'
        if( $f  > 57 && $f < 65 ) { $hostnameok = 0; last } # 57 = '9', 65 = 'A'
        if( $f  > 90            ) { $hostnameok = 0; last } # 90 = 'Z'
    }
    return 0 if $hostnameok == 0;

    my $p1 = rindex($argv0, ".");
    for my $e ( split("", substr($argv0, $p1 + 1,)) ) {
        # The top level domain should not include a number
        my $f = ord $e;
        if( $f > 47 && $f < 58 )  { $hostnameok = 0; last }
    }
    return $hostnameok;
}

1;
__END__
=encoding utf-8

=head1 NAME

Sisimai::RFC1123 - Internet hostname related class

=head1 SYNOPSIS

    use Sisimai::RFC1123;

    print Sisimai::RFC1123->is_internethost("mx2.example.jp"); # 1
    print Sisimai::RFC1123->is_internethost("localhost");      # 0


=head1 DESCRIPTION

C<Sisimai::RFC1123> is a class related to the Internet hosts

=head1 CLASS METHODS

=head2 C<B<is_internethost(I<String>)>>

C<is_internethost()> method returns true when the argument is a valid hostname

    print Sisimai::RFC1123->is_internethost("mx2.example.jp"); # 1
    print Sisimai::RFC1123->is_internethost("localhost");      # 0

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2024 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut

