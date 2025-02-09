package Sisimai::Reason::Blocked;
use v5.26;
use strict;
use warnings;
use Sisimai::String;

sub text { 'blocked' }
sub description { 'Email rejected due to client IP address or a hostname' }
sub match {
    # Try to match that the given text and regular expressions
    # @param    [String] argv1  String to be matched with regular expressions
    # @return   [Integer]       0: Did not match
    #                           1: Matched
    # @since v4.0.0
    my $class = shift;
    my $argv1 = shift // return undef;

    state $index = [
        ' said: 550 blocked',
        '//www.spamcop.net/bl.',
        'bad sender ip address',
        'banned sending ip',    # Office365
        'blacklisted by',
        'blocked using ',
        'blocked - see http',
        'dnsbl:attrbl',
        'client host rejected: abus detecte gu_eib_02',     # SFR
        'client host rejected: abus detecte gu_eib_04',     # SFR
        'client host rejected: may not be mail exchanger',
        'client host rejected: was not authenticated',      # Microsoft
        'confirm this mail server',
        'connection dropped',
        'connection refused by',
        'connection reset by peer',
        'connection was dropped by remote host',
        'connections not accepted from ip addresses on spamhaus xbl',
        'currently sending spam see: ',
        'domain does not exist:',
        'dynamic/zombied/spam ips blocked',
        'error: no valid recipients from ',
        'esmtp not accepting connections',  # icloud.com
        'extreme bad ip profile',
        'go away',
        'helo command rejected:',
        'host network not allowed',
        'hosts with dynamic ip',
        'invalid ip for sending mail of domain',
        'is in a black list',
        'is not allowed to send mail from',
        'no access from mail server',
        'no matches to nameserver query',
        'not currently accepting mail from your ip',    # Microsoft
        'part of their network is on our block list',
        'please use the smtp server of your isp',
        'refused - see http',
        'rejected - multi-blacklist',   # junkemailfilter.com
        'rejected because the sending mta or the sender has not passed validation',
        'rejecting open proxy', # Sendmail(srvrsmtp.c)
        'sender ip address rejected',
        'server access forbidden by your ip ',
        'service not available, closing transmission channel',
        'smtp error from remote mail server after initial connection:', # Exim
        "sorry, that domain isn't in my list of allowed rcpthosts",
        'sorry, your remotehost looks suspiciously like spammer',
        'temporarily deferred due to unexpected volume or user complaints',
        'to submit messages to this e-mail system has been rejected',
        'too many spams from your ip',  # free.fr
        'too many unwanted messages have been sent from the following ip address above',
        'was blocked by ',
        'we do not accept mail from dynamic ips',   # @mail.ru
        'you are not allowed to connect',
        'you are sending spam',
        'your ip address is listed in the rbl',
        'your network is temporary blacklisted',
        'your server requires confirmation',
    ];
    state $pairs = [
        ['(', '@', ':blocked)'],
        ['access from ip address ', ' blocked'],
        ['client host ', ' blocked using'],
        ['connections will not be accepted from ', " because the ip is in spamhaus's list"],
        ['dnsbl:rbl ', '>_is_blocked'],
        ['email blocked by ', '.barracudacentral.org'],
        ['email blocked by ', 'spamhaus'],
        ['host ', ' refused to talk to me: ', ' blocked'],
        ['ip ', ' is blocked by earthlink'],    # Earthlink
        ['is in an ', 'rbl on '],
        ['mail server at ', ' is blocked'],
        ['mail from ',' refused:'],
        ["mail from "," refused, see ", "orbs"],
        ['message from ', ' rejected based on blacklist'],
        ['messages from ', ' temporarily deferred due to user complaints'], # Yahoo!
        ['server ip ', ' listed as abusive'],
        ['sorry! your ip address', ' is blocked by rbl'], # junkemailfilter.com
        ['the domain ', ' is blacklisted'],
        ['the email ', ' is blacklisted'],
        ['the ip', ' is blacklisted'],
        ['veuillez essayer plus tard. service refused, please try later. ', '103'],
        ['veuillez essayer plus tard. service refused, please try later. ', '510'],
        ["your access ip", " has been rejected"],
        ["your sender's ip address is listed at ", '.abuseat.org'],
    ];
    return 1 if grep { rindex($argv1, $_) > -1 } @$index;
    return 1 if grep { Sisimai::String->aligned(\$argv1, $_) } @$pairs;
    return 0;
}

sub true {
    # Rejected due to client IP address or hostname
    # @param    [Sisimai::Fact] argvs   Object to be detected the reason
    # @return   [Integer]               1: is blocked
    #           [Integer]               0: is not blocked by the client
    # @see      http://www.ietf.org/rfc/rfc2822.txt
    # @since v4.0.0
    my $class = shift;
    my $argvs = shift // return undef;

    return 1 if $argvs->{'reason'} eq 'blocked';
    return 1 if (Sisimai::SMTP::Status->name($argvs->{'deliverystatus'}) || '') eq 'blocked';
    return __PACKAGE__->match(lc $argvs->{'diagnosticcode'});
}

1;
__END__

=encoding utf-8

=head1 NAME

Sisimai::Reason::Blocked - Bounce reason is "blocked" or not.

=head1 SYNOPSIS

    use Sisimai::Reason::Blocked;
    print Sisimai::Reason::Blocked->match('Access from ip address 192.0.2.1 blocked'); # 1

=head1 DESCRIPTION

C<Sisimai::Reason::Blocked> checks the bounce reason is C<blocked> or not. This class is called
only C<Sisimai::Reason> class.

This is the error that SMTP connection was rejected due to a client IP address or a hostname, or
the parameter of C<HELO> or C<EHLO> command. This reason has added in Sisimai 4.0.0.

    <kijitora@example.net>:
    Connected to 192.0.2.112 but my name was rejected.
    Remote host said: 501 5.0.0 Invalid domain name

=head1 CLASS METHODS

=head2 C<B<text()>>

C<text()> method returns the fixed string C<blocked>.

    print Sisimai::Reason::Blocked->text;  # blocked

=head2 C<B<match(I<string>)>>

C<match()> method returns C<1> if the argument matched with patterns defined in this class.

    print Sisimai::Reason::Blocked->match('Access from ip address 192.0.2.1 blocked');  # 1

=head2 C<B<true(I<Sisimai::Fact>)>>

C<true()> method returns C<1> if the bounce reason is C<blocked>. The argument must be C<Sisimai::Fact>
object and this method is called only from C<Sisimai::Reason> class.

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2014-2025 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut

