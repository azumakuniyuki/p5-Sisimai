package Sisimai::ARF;
use feature ':5.10';
use strict;
use warnings;
use Sisimai::Lhost;
use Sisimai::RFC5322;

sub description { return 'Abuse Feedback Reporting Format' }
sub is_arf {
    # Email is a Feedback-Loop message or not
    # @param    [Hash] heads    Email header including "Content-Type", "From" and "Subject" field
    # @return   [Integer]       1: Feedback Loop
    #                           0: is not Feedback loop
    my $class = shift;
    my $heads = shift || return 0;
    my $match = 0;

    state $reportfrom = qr/(?:staff[@]hotmail[.]com|complaints[@]email-abuse[.]amazonses[.]com)\z/;

    if( $heads->{'content-type'} =~ /report-type=["]?feedback-report["]?/ ) {
        # Content-Type: multipart/report; report-type=feedback-report; ...
        $match = 1;

    } elsif( index($heads->{'content-type'}, 'multipart/mixed') > -1 ) {
        # Microsoft (Hotmail, MSN, Live, Outlook) uses its own report format.
        # Amazon SES Complaints bounces
        my $p = Sisimai::Address->s3s4($heads->{'from'});
        if( $p =~ $reportfrom && index($heads->{'subject'}, 'complaint about message from ') > -1 ) {
            # From: staff@hotmail.com
            # From: complaints@email-abuse.amazonses.com
            # Subject: complaint about message from 192.0.2.1
            $match = 1;
        }
    }
    return $match;
}

sub make {
    # Detect an error for Feedback Loop
    # @param    [Hash] mhead    Message headers of a bounce email
    # @param    [String] mbody  Message body of a bounce email
    # @return   [Hash]          Bounce data list and message/rfc822 part
    # @return   [undef]         failed to parse or the arguments are missing
    my $class = shift;
    my $mhead = shift // return undef;
    my $mbody = shift // return undef;
    return undef unless is_arf(undef, $mhead);

    # http://tools.ietf.org/html/rfc5965
    # http://en.wikipedia.org/wiki/Feedback_loop_(email)
    # http://en.wikipedia.org/wiki/Abuse_Reporting_Format
    #
    # Netease DMARC uses:    This is a spf/dkim authentication-failure report for an email message received from IP
    # OpenDMARC 1.3.0 uses:  This is an authentication failure report for an email message received from IP
    # Abusix ARF uses:       this is an autogenerated email abuse complaint regarding your network.
    state $startingof = {
        'rfc822' => ['Content-Type: message/rfc822', 'Content-Type: text/rfc822-headers'],
        'report' => ['Content-Type: message/feedback-report'],
    };
    state $markingsof = {
        'message' => qr{\A(?>
             [Tt]his[ ]is[ ]a[ ][^ ]+[ ](?:email[ ])?[Aa]buse[ ][Rr]eport
            |[Tt]his[ ]is[ ]an[ ]email[ ]abuse[ ]report
            |[Tt]his[ ]is[ ](?:
                 a[ ][^ ]+[ ]authentication[ -]failure[ ]report
                |an[ ]authentication[ -]failure[ ]report
                |an[ ]autogenerated[ ]email[ ]abuse[ ]complaint
                |an?[ ][^ ]+[ ]report[ ]for
                )
            )
        }x,
    };
    state $indicators = Sisimai::Lhost->INDICATORS;
    state $longfields = Sisimai::RFC5322->LONGFIELDS;
    state $rfc822head = Sisimai::RFC5322->HEADERFIELDS;

    my $dscontents = [Sisimai::Lhost->DELIVERYSTATUS];
    my $rfc822part = '';    # (String) message/rfc822-headers part
    my $previousfn = '';    # (String) Previous field name
    my $readcursor = 0;     # (Integer) Points the current cursor position
    my $recipients = 0;     # (Integer) The number of 'Final-Recipient' header
    my $rcptintext = '';    # (String) Recipient address in the message body
    my $commondata = {
        'diagnosis'    => '',   # Error message
        'from'         => '',   # Original-Mail-From:
        'rhost'        => '',   # Reporting-MTA:
    };
    my $arfheaders = {
        'feedbacktype' => '',   # Feedback-Type:
        'rhost'        => '',   # Source-IP:
        'agent'        => '',   # User-Agent:
        'date'         => '',   # Arrival-Date:
        'authres'      => '',   # Authentication-Results:
    };
    my $v = undef;

    # 3.1.  Required Fields
    #
    #   The following report header fields MUST appear exactly once:
    #
    #   o  "Feedback-Type" contains the type of feedback report (as defined
    #      in the corresponding IANA registry and later in this memo).  This
    #      is intended to let report parsers distinguish among different
    #      types of reports.
    #
    #   o  "User-Agent" indicates the name and version of the software
    #      program that generated the report.  The format of this field MUST
    #      follow section 14.43 of [HTTP].  This field is for documentation
    #      only; there is no registry of user agent names or versions, and
    #      report receivers SHOULD NOT expect user agent names to belong to a
    #      known set.
    #
    #   o  "Version" indicates the version of specification that the report
    #      generator is using to generate the report.  The version number in
    #      this specification is set to "1".
    #
    for my $e ( split("\n", $$mbody) ) {
        # Read each line between the start of the message and the start of rfc822 part.

        # This is an email abuse report for an email message with the
        #   message-id of 0000-000000000000000000000000000000000@mx
        #   received from IP address 192.0.2.1 on
        #   Thu, 29 Apr 2010 00:00:00 +0900 (JST)
        $commondata->{'diagnosis'} ||= $e if $e =~ $markingsof->{'message'};

        unless( $readcursor ) {
            # Beginning of the bounce message or message/delivery-status part
            $readcursor |= $indicators->{'deliverystatus'} if index($e, $startingof->{'report'}->[0]) == 0;
        }

        unless( $readcursor & $indicators->{'message-rfc822'} ) {
            # Beginning of the original message part
            if( index($e, $startingof->{'rfc822'}->[0]) == 0 ||
                index($e, $startingof->{'rfc822'}->[1]) == 0 ) {
                $readcursor |= $indicators->{'message-rfc822'};
                next;
            }
        }

        if( $readcursor & $indicators->{'message-rfc822'} ) {
            # message/rfc822 OR text/rfc822-headers part
            if( $e =~ /X-HmXmrOriginalRecipient:[ ]*(.+)\z/ ) {
                # Microsoft ARF: original recipient.
                $dscontents->[-1]->{'recipient'} = Sisimai::Address->s3s4($1);
                $recipients++;

                # The "X-HmXmrOriginalRecipient" header appears only once so we take this opportunity
                # to hard-code ARF headers missing in Microsoft's implementation.
                $arfheaders->{'feedbacktype'} = 'abuse';
                $arfheaders->{'agent'} = 'Microsoft Junk Mail Reporting Program';

            } elsif( $e =~ /\AFrom:[ ]*(.+)\z/ ) {
                # Microsoft ARF: original sender.
                $commondata->{'from'} ||= Sisimai::Address->s3s4($1);
                $previousfn = 'from';

            } elsif( $e =~ /\A[ \t]+/ ) {
                # Continued line from the previous line
                if( $previousfn eq 'from' ) {
                    # Multiple lines at From: field
                    $commondata->{'from'} .= $e;
                    next;

                } else {
                    $rfc822part .= $e."\n" if exists $longfields->{ $previousfn };
                    next if length $e;
                }
                $rcptintext .= $e if $previousfn eq 'to';

            } else {
                # Get required headers only
                my($lhs, $rhs) = split(/:[ ]*/, $e, 2);
                next unless $lhs = lc($lhs || '');

                $previousfn = '';
                next unless exists $rfc822head->{ $lhs };

                $previousfn  = $lhs;
                $rfc822part .= $e."\n";
                $rcptintext  = $rhs if $lhs eq 'to';
            }
        } else {
            # message/feedback-report part
            next unless $readcursor & $indicators->{'deliverystatus'};
            next unless length $e;

            # Feedback-Type: abuse
            # User-Agent: SomeGenerator/1.0
            # Version: 0.1
            # Original-Mail-From: <somespammer@example.net>
            # Original-Rcpt-To: <kijitora@example.jp>
            # Received-Date: Thu, 29 Apr 2009 00:00:00 JST
            # Source-IP: 192.0.2.1
            $v = $dscontents->[-1];

            if( $e =~ /\AOriginal-Rcpt-To:[ ]+[<]?(.+)[>]?\z/ ||
                $e =~ /\ARedacted-Address:[ ]([^ ].+[@])\z/ ) {
                # Original-Rcpt-To header field is optional and may appear any
                # number of times as appropriate:
                # Original-Rcpt-To: <user@example.com>
                # Redacted-Address: localpart@
                if( $v->{'recipient'} ) {
                    # There are multiple recipient addresses in the message body.
                    push @$dscontents, Sisimai::Lhost->DELIVERYSTATUS;
                    $v = $dscontents->[-1];
                }
                $v->{'recipient'} = Sisimai::Address->s3s4($1);
                $recipients++;

            } elsif( $e =~ /\AFeedback-Type:[ ]*([^ ]+)\z/ ) {
                # The header field MUST appear exactly once.
                # Feedback-Type: abuse
                $arfheaders->{'feedbacktype'} = $1;

            } elsif( $e =~ /\AAuthentication-Results:[ ]*(.+)\z/ ) {
                # "Authentication-Results" indicates the result of one or more authentication checks
                # run by the report generator.
                #
                # Authentication-Results: mail.example.com;
                #   spf=fail smtp.mail=somespammer@example.com
                $arfheaders->{'authres'} = $1;

            } elsif( $e =~ /\AUser-Agent:[ ]*(.+)\z/ ) {
                # The header field MUST appear exactly once.
                # User-Agent: SomeGenerator/1.0
                $arfheaders->{'agent'} = $1;

            } elsif( $e =~ /\A(?:Received|Arrival)-Date:[ ]*(.+)\z/ ) {
                # Arrival-Date header is optional and MUST NOT appear more than once.
                # Received-Date: Thu, 29 Apr 2010 00:00:00 JST
                # Arrival-Date: Thu, 29 Apr 2010 00:00:00 +0000
                $arfheaders->{'date'} = $1;

            } elsif( $e =~ /\AReporting-MTA:[ ]*dns;[ ]*(.+)\z/ ) {
                # The header is optional and MUST NOT appear more than once.
                # Reporting-MTA: dns; mx.example.jp
                $commondata->{'rhost'} = $1;

            } elsif( $e =~ /\ASource-I[Pp]:[ ]*(.+)\z/ ) {
                # The header is optional and MUST NOT appear more than once.
                # Source-IP: 192.0.2.45
                $arfheaders->{'rhost'} = $1;

            } elsif( $e =~ /\AOriginal-Mail-From:[ ]*(.+)\z/ ) {
                # the header is optional and MUST NOT appear more than once.
                # Original-Mail-From: <somespammer@example.net>
                $commondata->{'from'} ||= Sisimai::Address->s3s4($1);
            }
        } # End of if: rfc822
    }

    if( ($arfheaders->{'feedbacktype'} eq 'auth-failure' ) && $arfheaders->{'authres'} ) {
        # Append the value of Authentication-Results header
        $commondata->{'diagnosis'} .= ' '.$arfheaders->{'authres'}
    }

    unless( $recipients ) {
        # The original recipient address was not found
        if( $rfc822part =~ /^To: (.+[@].+)$/m ) {
            # pick the address from To: header in message/rfc822 part.
            $dscontents->[-1]->{'recipient'} = Sisimai::Address->s3s4($1);

        } else {
            # Insert pseudo recipient address when there is no valid recipient address in the message.
            $dscontents->[-1]->{'recipient'} = Sisimai::Address->undisclosed('r');
        }
        $recipients = 1;
    }

    unless( $rfc822part =~ /\bFrom: [^ ]+[@][^ ]+\b/ ) {
        # There is no "From:" header in the original message Append the value of "Original-Mail-From"
        # value as a sender address.
        $rfc822part .= 'From: '.$commondata->{'from'}."\n" if $commondata->{'from'};
    }

    if( $mhead->{'subject'} =~ /complaint about message from (\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3})/ ) {
        # Microsoft ARF: remote host address.
        $arfheaders->{'rhost'} = $1;
        $commondata->{'diagnosis'} = sprintf(
            "This is a Microsoft email abuse report for an email message received from IP %s on %s",
            $arfheaders->{'rhost'}, $mhead->{'date'});
    }

    for my $e ( @$dscontents ) {
        # AOL = http://forums.cpanel.net/f43/aol-brutal-work-71473.html
        $e->{'recipient'} = Sisimai::Address->s3s4($rcptintext) if $e->{'recipient'} =~ /\A[^ ]+[@]\z/;
        $e->{ $_ } ||= $arfheaders->{ $_ } for keys %$arfheaders;
        delete $e->{'authres'};

        $e->{'diagnosis'} ||= $commondata->{'diagnosis'};
        $e->{'diagnosis'}   = Sisimai::String->sweep($e->{'diagnosis'});
        $e->{'date'}      ||= $mhead->{'date'};
        $e->{'reason'}  = 'feedback';
        $e->{'command'} = '';
        $e->{'action'}  = '';
        $e->{'agent'}   = 'Feedback-Loop';

        # Get the remote IP address from the message body
        next if $e->{'rhost'};
        if( $commondata->{'rhost'} ) {
            # The value of "Reporting-MTA" header
            $e->{'rhost'} = $commondata->{'rhost'};

        } elsif( $e->{'diagnosis'} =~ /\breceived from IP address ([^ ]+)/ ) {
            # This is an email abuse report for an email message received from IP address 24.64.1.1
            # on Thu, 29 Apr 2010 00:00:00 +0000
            $e->{'rhost'} = $1;
        }
    }
    return { 'ds' => $dscontents, 'rfc822' => $rfc822part };
}

1;
__END__

=encoding utf-8

=head1 NAME

Sisimai::ARF - Parser class for detecting ARF: Abuse Feedback Reporting Format.

=head1 SYNOPSIS

Do not use this class directly, use Sisimai::ARF.

    use Sisimai::ARF;
    my $v = Sisimai::ARF->make($header, $body);

=head1 DESCRIPTION

Sisimai::ARF is a parser for email returned as a Feedback Loop report message.

=head1 FEEDBACK TYPES

=head2 B<abuse>

Unsolicited email or some other kind of email abuse.

=head2 B<fraud>

Indicates some kind of C<fraud> or C<phishing> activity.

=head2 B<other>

Any other feedback that does not fit into other registered types.

=head2 B<virus>

Report of a virus found in the originating message.

=head1 SEE ALSO

L<http://tools.ietf.org/html/rfc5965>

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2014-2021 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut
