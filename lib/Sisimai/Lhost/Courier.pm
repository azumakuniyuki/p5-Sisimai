package Sisimai::Lhost::Courier;
use parent 'Sisimai::Lhost';
use v5.26;
use strict;
use warnings;

sub description { 'Courier MTA' }
sub inquire {
    # Detect an error from Courier MTA
    # @param    [Hash] mhead    Message headers of a bounce email
    # @param    [String] mbody  Message body of a bounce email
    # @return   [Hash]          Bounce data list and message/rfc822 part
    # @return   [undef]         failed to decode or the arguments are missing
    # @since v4.0.0
    my $class = shift;
    my $mhead = shift // return undef;
    my $mbody = shift // return undef;
    my $match = 0;

    $match ||= 1 if index($mhead->{'from'},    'Courier mail server at ')       > -1;
    $match ||= 1 if index($mhead->{'subject'}, 'NOTICE: mail delivery status.') > -1;
    $match ||= 1 if index($mhead->{'subject'}, 'WARNING: delayed mail.')        > -1;
    if( defined $mhead->{'message-id'} ) {
        # Message-ID: <courier.4D025E3A.00001792@5jo.example.org>
        $match ||= 1 if index($mhead->{'message-id'}, '<courier.') == 0;
    }
    return undef unless $match;

    require Sisimai::RFC1123;
    require Sisimai::SMTP::Command;
    state $indicators = __PACKAGE__->INDICATORS;
    state $boundaries = ['Content-Type: :message/rfc822', 'Content-Type: text/rfc822-headers'];
    state $startingof = {
        # https://www.courier-mta.org/courierdsn.html
        # courier/module.dsn/dsn*.txt
        'message' => ['DELAYS IN DELIVERING YOUR MESSAGE', 'UNDELIVERABLE MAIL'],
    };
    state $messagesof = {
        # courier/module.esmtp/esmtpclient.c:526| hard_error(del, ctf, "No such domain.");
        'hostunknown' => ['No such domain.'],
        # courier/module.esmtp/esmtpclient.c:531| hard_error(del, ctf,
        # courier/module.esmtp/esmtpclient.c:532|  "This domain's DNS violates RFC 1035.");
        'systemerror' => ["This domain's DNS violates RFC 1035."],
        # courier/module.esmtp/esmtpclient.c:535| soft_error(del, ctf, "DNS lookup failed.");
        'networkerror'=> ['DNS lookup failed.'],
    };

    my $fieldtable = Sisimai::RFC1894->FIELDTABLE;
    my $permessage = {};    # (Hash) Store values of each Per-Message field
    my $dscontents = [__PACKAGE__->DELIVERYSTATUS];
    my $emailparts = Sisimai::RFC5322->part($mbody, $boundaries);
    my $readcursor = 0;     # (Integer) Points the current cursor position
    my $recipients = 0;     # (Integer) The number of 'Final-Recipient' header
    my $thecommand = '';    # (String) SMTP Command name begin with the string '>>>'
    my $v = undef;
    my $p = '';

    for my $e ( split("\n", $emailparts->[0]) ) {
        # Read error messages and delivery status lines from the head of the email to the previous
        # line of the beginning of the original message.
        unless( $readcursor ) {
            # Beginning of the bounce message or message/delivery-status part
            if( rindex($e, $startingof->{'message'}->[0]) > -1 ||
                rindex($e, $startingof->{'message'}->[1]) > -1 ) {
                $readcursor |= $indicators->{'deliverystatus'};
                next;
            }
        }
        next unless $readcursor & $indicators->{'deliverystatus'};
        next unless length $e;

        if( my $f = Sisimai::RFC1894->match($e) ) {
            # $e matched with any field defined in RFC3464
            next unless my $o = Sisimai::RFC1894->field($e);
            $v = $dscontents->[-1];

            if( $o->[3] eq 'addr' ) {
                # Final-Recipient: rfc822; kijitora@example.jp
                # X-Actual-Recipient: rfc822; kijitora@example.co.jp
                if( $o->[0] eq 'final-recipient' ) {
                    # Final-Recipient: rfc822; kijitora@example.jp
                    if( $v->{'recipient'} ) {
                        # There are multiple recipient addresses in the message body.
                        push @$dscontents, __PACKAGE__->DELIVERYSTATUS;
                        $v = $dscontents->[-1];
                    }
                    $v->{'recipient'} = $o->[2];
                    $recipients++;

                } else {
                    # X-Actual-Recipient: rfc822; kijitora@example.co.jp
                    $v->{'alias'} = $o->[2];
                }
            } elsif( $o->[3] eq 'code' ) {
                # Diagnostic-Code: SMTP; 550 5.1.1 <userunknown@example.jp>... User Unknown
                $v->{'spec'} = $o->[1];
                $v->{'diagnosis'} = $o->[2];

            } else {
                # Other DSN fields defined in RFC3464
                next unless exists $fieldtable->{ $o->[0] };
                next if $o->[3] eq "host" && Sisimai::RFC1123->is_internethost($o->[2]) == 0;
                $v->{ $fieldtable->{ $o->[0] } } = $o->[2];

                next unless $f == 1;
                $permessage->{ $fieldtable->{ $o->[0] } } = $o->[2];
            }
        } else {
            # The line does not begin with a DSN field defined in RFC3464
            #
            # This is a delivery status notification from marutamachi.example.org,
            # running the Courier mail server, version 0.65.2.
            #
            # The original message was received on Sat, 11 Dec 2010 12:19:57 +0900
            # from [127.0.0.1] (c10920.example.com [192.0.2.20])
            #
            # ---------------------------------------------------------------------------
            #
            #                           UNDELIVERABLE MAIL
            #
            # Your message to the following recipients cannot be delivered:
            #
            # <kijitora@example.co.jp>:
            #    mx.example.co.jp [74.207.247.95]:
            # >>> RCPT TO:<kijitora@example.co.jp>
            # <<< 550 5.1.1 <kijitora@example.co.jp>... User Unknown
            #
            # ---------------------------------------------------------------------------
            if( index($e, '>>> ') == 0 ) {
                # >>> DATA
                $thecommand = Sisimai::SMTP::Command->find($e);

            } else {
                # Continued line of the value of Diagnostic-Code field
                next unless index($p, 'Diagnostic-Code:') == 0;
                next unless index($e, ' ') == 0;
                $v->{'diagnosis'} .= ' '.Sisimai::String->sweep($e);
            }
        }
    } continue {
        # Save the current line for the next loop
        $p = $e;
    }
    return undef unless $recipients;

    for my $e ( @$dscontents ) {
        # Set default values if each value is empty.
        $e->{ $_ } ||= $permessage->{ $_ } || '' for keys %$permessage;
        $e->{'diagnosis'} = Sisimai::String->sweep($e->{'diagnosis'});

        for my $r ( keys %$messagesof ) {
            # Verify each regular expression of session errors
            next unless grep { index($e->{'diagnosis'}, $_) > -1 } $messagesof->{ $r }->@*;
            $e->{'reason'} = $r;
            last;
        }
        $e->{'command'} ||= $thecommand || '';
    }
    return { 'ds' => $dscontents, 'rfc822' => $emailparts->[1] };
}

1;
__END__

=encoding utf-8

=head1 NAME

Sisimai::Lhost::Courier - bounce mail decoder class for Courier MTA L<https://www.courier-mta.org/>.

=head1 SYNOPSIS

    use Sisimai::Lhost::Courier;

=head1 DESCRIPTION

C<Sisimai::Lhost::Courier> decodes a bounce email which created by Courier MTA L<https://www.courier-mta.org/>.
Methods in the module are called from only C<Sisimai::Message>.

=head1 CLASS METHODS

=head2 C<B<description()>>

C<description()> returns description string of this module.

    print Sisimai::Lhost::Courier->description;

=head2 C<B<inquire(I<header data>, I<reference to body string>)>>

C<inquire()> method decodes a bounced email and return results as a array reference.
See C<Sisimai::Message> for more details.

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2014-2025 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut

