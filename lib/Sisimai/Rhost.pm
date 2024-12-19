package Sisimai::Rhost;
use v5.26;
use strict;
use warnings;

state $RhostClass = {
    "Aol"         => [".mail.aol.com", ".mx.aol.com"],
    "Apple"       => [".mail.icloud.com", ".apple.com", ".me.com"],
    "Cox"         => ["cox.net"],
    "Facebook"    => [".facebook.com"],
    "FrancePTT"   => [".laposte.net", ".orange.fr", ".wanadoo.fr"],
    "GoDaddy"     => ["smtp.secureserver.net", "mailstore1.secureserver.net"],
    "Google"      => ["aspmx.l.google.com", "gmail-smtp-in.l.google.com"],
    "GSuite"      => ["googlemail.com"],
    "IUA"         => [".email.ua"],
    "KDDI"        => [".ezweb.ne.jp", "msmx.au.com"],
    "MessageLabs" => [".messagelabs.com"],
    "Microsoft"   => [".prod.outlook.com", ".protection.outlook.com", ".onmicrosoft.com", ".exchangelabs.com",],
    "Mimecast"    => [".mimecast.com"],
    "NTTDOCOMO"   => ["mfsmax.docomo.ne.jp"],
    "Outlook"     => [".hotmail.com"],
    "Spectrum"    => ["charter.net"],
    "Tencent"     => [".qq.com"],
    "YahooInc"    => [".yahoodns.net"],
};

sub find {
    # Detect the bounce reason from certain remote hosts
    # @param    [Sisimai::Fact] argvs   Decoded email object
    # @return   [String]                The value of bounce reason
    my $class = shift;
    my $argvs = shift || return undef;
    return undef unless length $argvs->{'diagnosticcode'};

    my $rhostclass = '';
    my $clienthost = lc $argvs->{'lhost'}       || '';
    my $remotehost = lc $argvs->{'rhost'}       || '';
    my $domainpart = lc $argvs->{'destination'} || '';
    return undef unless length $remotehost.$domainpart;

    FINDRHOST: while( $rhostclass eq "" ) {
        # Try to match the hostname patterns with the following order:
        # 1. destination: The domain part of the recipient address
        # 2. rhost: remote hostname
        # 3. lhost: local MTA hostname
        for my $e ( keys %$RhostClass ) {
            # Try to match the domain part with each value of RhostClass
            next unless grep { index($_, $domainpart) > -1 } $RhostClass->{ $e }->@*;
            $rhostclass = __PACKAGE__.'::'.$e; last FINDRHOST;
        }

        for my $e ( keys %$RhostClass ) {
            # Try to match the remote host with each value of RhostClass
            next unless grep { index($remotehost, $_) > -1 } $RhostClass->{ $e }->@*;
            $rhostclass = __PACKAGE__.'::'.$e; last FINDRHOST;
        }

        # Neither the remote host nor the destination did not matched with any value of RhostClass
        for my $e ( keys %$RhostClass ) {
            # Try to match the client host with each value of RhostClass
            next unless grep { index($clienthost, $_) > -1 } $RhostClass->{ $e }->@*;
            $rhostclass = __PACKAGE__."::".$e; last FINDRHOST;
        }
        last;
    }
    return undef unless $rhostclass;

    (my $modulepath = $rhostclass) =~ s|::|/|g;
    require $modulepath.'.pm';
    return $rhostclass->find($argvs);
}

1;
__END__

=encoding utf-8

=head1 NAME

Sisimai::Rhost - Detect the bounce reason returned from certain remote hosts.

=head1 SYNOPSIS

    use Sisimai::Rhost;

=head1 DESCRIPTION

C<Sisimai::Rhost> detects the bounce reason from the content of C<Sisimai::Fact> object as an argument
of C<find()> method when the value of C<rhost> of the object is listed in C<$RhostClass> variable.
This class is called only C<Sisimai::Fact> class.

=head1 CLASS METHODS

=head2 C<B<find(I<Sisimai::Fact Object>)>>

C<find()> method detects the bounce reason.

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2014-2020,2022-2024 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut

