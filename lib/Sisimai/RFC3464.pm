package Sisimai::RFC3464;
use feature ':5.10';
use strict;
use warnings;
use Sisimai::Lhost;

# http://tools.ietf.org/html/rfc3464
sub description { 'Fallback Module for MTAs' };
sub inquire {
    # Detect an error for RFC3464
    # @param    [Hash] mhead    Message headers of a bounce email
    # @param    [String] mbody  Message body of a bounce email
    # @return   [Hash]          Bounce data list and message/rfc822 part
    # @return   [undef]         failed to parse or the arguments are missing
    my $class = shift;
    my $mhead = shift // return undef;
    my $mbody = shift // return undef;
    my $match = 0;

    return undef unless keys %$mhead;
    return undef unless ref $mbody eq 'SCALAR';

    state $indicators = Sisimai::Lhost->INDICATORS;
    state $markingsof = {
        'command' => qr/[ ](RCPT|MAIL|DATA)[ ]+command\b/,
        'message' => qr{\A(?>
             content-type:[ ]*(?:
                  message/x?delivery-status
                 |message/disposition-notification
                 |text/plain;[ ]charset=
                 )
            |the[ ]original[ ]message[ ]was[ ]received[ ]at[ ]
            |this[ ]report[ ]relates[ ]to[ ]your[ ]message
            |your[ ]message[ ](?:
                could[ ]not[ ]be[ ]delivered
               |was[ ]not[ ]delivered[ ]to[ ](?:the[ ]following[ ]recipients)?
               )
            )
        }x,
        'error'  => qr/\A(?:[45]\d\d[ \t]+|[<][^@]+[@][^@]+[>]:?[ \t]+)/,
        'rfc822' => qr{\A(?>
             content-type:[ ]*(?:message/rfc822|text/rfc822-headers)
            |return-path:[ ]*[<].+[>]
            )\z
        }x,
    };

    my $dscontents = [Sisimai::Lhost->DELIVERYSTATUS];
    my $rfc822text = '';    # (String) message/rfc822 part text
    my $maybealias = '';    # (String) Original-Recipient field
    my $lowercased = '';    # (String) Lowercased each line of the loop
    my $blanklines = 0;     # (Integer) The number of blank lines
    my $readcursor = 0;     # (Integer) Points the current cursor position
    my $recipients = 0;     # (Integer) The number of 'Final-Recipient' header
    my $itisbounce = 0;     # (Integer) Flag for that an email is a bounce
    my $connheader = {
        'date'    => '',    # The value of Arrival-Date header
        'rhost'   => '',    # The value of Reporting-MTA header
        'lhost'   => '',    # The value of Received-From-MTA header
    };
    my $v = undef;
    my $p = '';

    for my $e ( split("\n", $$mbody) ) {
        # Read each line between the start of the message and the start of rfc822 part.
        $lowercased = lc $e;
        unless( $readcursor ) {
            # Beginning of the bounce message or message/delivery-status part
            if( $lowercased =~ $markingsof->{'message'} ) {
                $readcursor |= $indicators->{'deliverystatus'};
                next;
            }
        }

        unless( $readcursor & $indicators->{'message-rfc822'} ) {
            # Beginning of the original message part(message/rfc822)
            if( $lowercased =~ $markingsof->{'rfc822'} ) {
                $readcursor |= $indicators->{'message-rfc822'};
                next;
            }
        }

        if( $readcursor & $indicators->{'message-rfc822'} ) {
            # message/rfc822 OR text/rfc822-headers part
            unless( length $e ) {
                last if ++$blanklines > 1;
                next;
            }
            $rfc822text .= sprintf("%s\n", $e);

        } else {
            # message/delivery-status part
            next unless $readcursor & $indicators->{'deliverystatus'};
            next unless length $e;

            $v = $dscontents->[-1];
            if( $e =~ /\A(Original|Final)-[Rr]ecipient:[ ]*.+;[ ]*([^ ]+)\z/ ) {
                # 2.3.2 Final-Recipient field
                #   The Final-Recipient field indicates the recipient for which this set of per-re-
                #   cipient fields applies.  This field MUST be present in each set of per-recipi-
                #   ent data. The syntax of the field is as follows:
                #
                #       final-recipient-field =
                #           "Final-Recipient" ":" address-type ";" generic-address
                #
                # 2.3.1 Original-Recipient field
                #   The Original-Recipient field indicates the original recipient address as speci-
                #   fied by the sender of the message for which the DSN is being issued.
                #
                #       original-recipient-field =
                #           "Original-Recipient" ":" address-type ";" generic-address
                #
                #       generic-address = *text
                if( $1 eq 'Original' ) {
                    # Original-Recipient: ...
                    $maybealias = $2;

                } else {
                    # Final-Recipient: ...
                    my $x = $v->{'recipient'} || '';
                    my $y = Sisimai::Address->s3s4($2);
                       $y = $maybealias unless Sisimai::Address->is_emailaddress($y);

                    if( $x && $x ne $y ) {
                        # There are multiple recipient addresses in the message body.
                        push @$dscontents, Sisimai::Lhost->DELIVERYSTATUS;
                        $v = $dscontents->[-1];
                    }
                    $v->{'recipient'} = $y;
                    $recipients++;
                    $itisbounce ||= 1;

                    $v->{'alias'} ||= $maybealias;
                    $maybealias = '';
                }
            } elsif( $e =~ /\AX-Actual-Recipient:[ ]*(?:RFC|rfc)822;[ ]*([^ ]+)\z/ ) {
                # X-Actual-Recipient: RFC822; |IFS=' ' && exec procmail -f- || exit 75 ...
                # X-Actual-Recipient: rfc822; kijitora@neko.example.jp
                $v->{'alias'} = $1 unless $1 =~ /[ \t]+/;

            } elsif( $e =~ /\AAction:[ ]*(.+)\z/ ) {
                # 2.3.3 Action field
                #   The Action field indicates the action performed by the Reporting-MTA as a re-
                #   sult of its attempt to deliver the message to this recipient address.
                #   This field MUST be present for each recipient named in the DSN. The syntax for
                #   the action-field is:
                #
                #       action-field = "Action" ":" action-value
                #       action-value =
                #           "failed" / "delayed" / "delivered" / "relayed" / "expanded"
                #
                #   The action-value may be spelled in any combination of upper and lower case char-
                #   acters.
                $v->{'action'} = lc $1;
                $v->{'action'} = $1 if $v->{'action'} =~ /\A([^ ]+)[ ]/; # failed (bad destination mailbox address)

            } elsif( $e =~ /\AStatus:[ ]*(\d[.]\d+[.]\d+)/ ) {
                # 2.3.4 Status field
                #   The per-recipient Status field contains a transport-independent status code
                #   that indicates the delivery status of the message to that recipient. This field
                #   MUST be present for each delivery attempt which is described by a DSN.
                #
                #   The syntax of the status field is:
                #
                #       status-field = "Status" ":" status-code
                #       status-code = DIGIT "." 1*3DIGIT "." 1*3DIGIT
                $v->{'status'} = $1;

            } elsif( $e =~ /\AStatus:[ ]*(\d+[ ]+.+)\z/ ) {
                # Status: 553 Exceeded maximum inbound message size
                $v->{'alterrors'} = $1;

            } elsif( $e =~ /Remote-MTA:[ ]*(?:DNS|dns);[ ]*(.+)\z/ ) {
                # 2.3.5 Remote-MTA field
                #   The value associated with the Remote-MTA DSN field is a printable ASCII repre-
                #   sentation of the name of the "remote" MTA that reported delivery status to the
                #   "reporting" MTA.
                #
                #       remote-mta-field = "Remote-MTA" ":" mta-name-type ";" mta-name
                #
                #   NOTE: The Remote-MTA field preserves the "while talking to" information that
                #         was provided in some pre-existing nondelivery reports.
                #
                #   This field is optional.  It MUST NOT be included if no remote MTA was involved
                #   in the attempted delivery of the message to that recipient.
                $v->{'rhost'} = lc $1;

            } elsif( $e =~ /\ALast-Attempt-Date:[ ]*(.+)\z/ ) {
                # 2.3.7 Last-Attempt-Date field
                #   The Last-Attempt-Date field gives the date and time of the last attempt to re-
                #   lay, gateway, or deliver the message (whether successful or unsuccessful) by
                #   the Reporting MTA. This is not necessarily the same as the value of the Date
                #   field from the header of the message used to transmit this delivery status no-
                #   tification: In cases where the DSN was generated by a gateway, the Date field
                #   in the message header contains the time the DSN was sent by the gateway and the
                #   DSN Last-Attempt-Date field contains the time the last delivery attempt occurr-
                #   ed.
                #
                #       last-attempt-date-field = "Last-Attempt-Date" ":" date-time
                $v->{'date'} = $1;

            } else {
                if( $e =~ /\ADiagnostic-Code:[ ]*(.+?);[ ]*(.+)\z/ ) {
                    # 2.3.6 Diagnostic-Code field
                    #   For a "failed" or "delayed" recipient, the Diagnostic-Code DSN field con-
                    #   tains the actual diagnostic code issued by the mail transport. Since such
                    #   codes vary from one mail transport to another, the diagnostic-type subfield
                    #   is needed to specify which type of diagnostic code is represented.
                    #
                    #       diagnostic-code-field =
                    #           "Diagnostic-Code" ":" diagnostic-type ";" *text
                    $v->{'spec'} = uc $1;
                    $v->{'diagnosis'} = $2;

                } elsif( $e =~ /\ADiagnostic-Code:[ ]*(.+)\z/ ) {
                    # No value of "diagnostic-type"
                    # Diagnostic-Code: 554 ...
                    $v->{'diagnosis'} = $1;

                } elsif( index($p, 'Diagnostic-Code:') == 0 && $e =~ /\A[ \t]+(.+)\z/ ) {
                    # Continued line of the value of Diagnostic-Code header
                    $v->{'diagnosis'} .= ' '.$1;
                    $e = 'Diagnostic-Code: '.$e;

                } else {
                    if( $e =~ /\AReporting-MTA:[ ]*(?:DNS|dns);[ ]*(.+)\z/ ) {
                        # 2.2.2 The Reporting-MTA DSN field
                        #
                        #       reporting-mta-field =
                        #           "Reporting-MTA" ":" mta-name-type ";" mta-name
                        #       mta-name = *text
                        #
                        #   The Reporting-MTA field is defined as follows:
                        #
                        #   A DSN describes the results of attempts to deliver, relay, or gateway a
                        #   message to one or more recipients.  In all cases, the Reporting-MTA is
                        #   the MTA that attempted to perform the delivery, relay, or gateway oper-
                        #   ation described in the DSN.  This field is required.
                        $connheader->{'rhost'} ||= lc $1;

                    } elsif( $e =~ /\AReceived-From-MTA:[ ]*(?:DNS|dns);[ ]*(.+)\z/ ) {
                        # 2.2.4 The Received-From-MTA DSN field
                        #   The optional Received-From-MTA field indicates the name of the MTA from
                        #   which the message was received.
                        #
                        #       received-from-mta-field =
                        #           "Received-From-MTA" ":" mta-name-type ";" mta-name
                        #
                        #   If the message was received from an Internet host via SMTP, the con-
                        #   tents of the mta-name sub-field SHOULD be the Internet domain name sup-
                        #   plied in the HELO or EHLO command, and the network address used by the
                        #   SMTP client SHOULD be included as a comment enclosed in parentheses.
                        #   (In this case, the MTA-name-type will be "dns".)
                        $connheader->{'lhost'} = lc $1;

                    } elsif( $e =~ /\AArrival-Date:[ ]*(.+)\z/ ) {
                        # 2.2.5 The Arrival-Date DSN field
                        #   The optional Arrival-Date field indicates the date and time at which
                        #   the message arrived at the Reporting MTA.  If the Last-Attempt-Date
                        #   field is also provided in a per-recipient field, this can be used to
                        #   determine the interval between when the message arrived at the Report-
                        #   ing MTA and when the report was issued for that recipient.
                        #
                        #       arrival-date-field = "Arrival-Date" ":" date-time
                        $connheader->{'date'} = $1;

                    } else {
                        # Get error message
                        next if $e =~ /\A[ -]+/;
                        next unless $e =~ $markingsof->{'error'};

                        # 500 User Unknown
                        # <kijitora@example.jp> Unknown
                        $v->{'alterrors'} .= ' '.$e;
                    }
                }
            }
        } # End of message/delivery-status
    } continue {
        # Save the current line for the next loop
        $p = $e;
    }

    # ---------------------------------------------------------------------------------------------
    BODY_PARSER_FOR_FALLBACK: {
        # Fallback, parse entire message body
        last if $recipients;

        # Failed to get a recipient address at code above
        my $returnpath = lc($mhead->{'return-path'} // '');
        my $headerfrom = lc($mhead->{'from'}        // '');
        my $errortitle = lc($mhead->{'subject'}     // '');
        my $patternsof = {
            'from'        => ['postmaster@', 'mailer-daemon@', 'root@'],
            'return-path' => ['<>', 'mailer-daemon'],
            'subject'     => ['delivery fail', 'delivery report', 'failure notice', 'mail delivery',
                              'mail failed', 'mail error', 'non-delivery', 'returned mail',
                              'undeliverable mail', 'warning: '],
        };

        $match ||= 1 if grep { index($headerfrom, $_) > -1 } $patternsof->{'from'}->@*;
        $match ||= 1 if grep { index($errortitle, $_) > -1 } $patternsof->{'subject'}->@*;
        $match ||= 1 if grep { index($returnpath, $_) > -1 } $patternsof->{'return-path'}->@*;
        last unless $match;

        state $readuntil0 = [
            # Stop reading when the following string have appeared at the first of a line
            'a copy of the original message below this line:',
            'content-type: message/delivery-status',
            'for further assistance, please contact ',
            'here is a copy of the first part of the message',
            'received:',
            'received-from-mta:',
            'reporting-mta:',
            'reporting-ua:',
            'return-path:',
            'the non-delivered message is attached to this message',
        ];
        state $readuntil1 = [
            # Stop reading when the following string have appeared in a line
            'attachment is a copy of the message',
            'below is a copy of the original message:',
            'below this line is a copy of the message',
            'message contains ',
            'message text follows: ',
            'original message follows',
            'the attachment contains the original mail headers',
            'the first ',
            'unsent message below',
            'your message reads (in part):',
        ];
        state $readafter0 = [
            # Do not read before the following strings
            '	the postfix ',
            'a summary of the undelivered message you sent follows:',
            'the following is the error message',
            'the message that you sent was undeliverable to the following',
            'your message was not delivered to ',
        ];
        state $donotread0 = ['   -----', ' -----', '--', '|--', '*'];
        state $donotread1 = ['mail from:'];
        state $reademail0 = [' ', '"', '<',];
        state $reademail1 = [
            # There is an email address around the following strings
            'address:',
            'addressed to',
            'could not be delivered to:',
            'delivered to',
            'delivery failed:',
            'did not reach the following recipient:',
            'error-for:',
            'failed recipient:',
            'failed to deliver to',
            'intended recipient:',
            'mailbox is full:',
            'recipient:',
            'rcpt to:',
            'smtp server <',
            'the following recipients returned permanent errors:',
            'the following addresses had permanent errors',
            'the following message to',
            'to: ',
            'unknown user:',
            'unable to deliver mail to the following recipient',
            'undeliverable to',
            'undeliverable address:',
            'you sent mail to',
            'your message has encountered delivery problems to the following recipients:',
            'was automatically rejected',
            'was rejected due to',
        ];

        my $b = $dscontents->[-1];
        my $hasmatched = 0;     # There may be an email address around the line
        my $readslices = [];    # Previous line of this loop
           $lowercased = lc $$mbody;

        for my $e ( @$readafter0 ) {
            # Cut strings from the begining of $$mbody to the strings defined in $readafter0
            my $i = index($lowercased, $e); next if $i == -1;
            $$mbody = substr($$mbody, $i);
        }

        for my $e ( split("\n", $$mbody) ) {
            # Get the recipient's email address and error messages.
            next unless length $e;

            $hasmatched = 0;
            $lowercased = lc $e;
            push @$readslices, $lowercased;

            last if $lowercased =~ $markingsof->{'rfc822'};
            last if grep { index($lowercased, $_) == 0 } @$readuntil0;
            last if grep { index($lowercased, $_) > -1 } @$readuntil1;
            next if grep { index($lowercased, $_) == 0 } @$donotread0;
            next if grep { index($lowercased, $_) > -1 } @$donotread1;

            while(1) {
                # There is an email address with an error message at this line(1)
                last unless grep { index($lowercased, $_) == 0 } @$reademail0;
                last unless index($lowercased, '@') > 1;

                $hasmatched = 1;
                last;
            }

            while(2) {
                # There is an email address with an error message at this line(2)
                last if $hasmatched > 0;
                last unless grep { index($lowercased, $_) > -1 } @$reademail1;
                last unless index($lowercased, '@') > 1;

                $hasmatched = 2;
                last;
            }

            while(3) {
                # There is an email address without an error message at this line
                last if $hasmatched > 0;
                last if scalar @$readslices < 2;
                last unless grep { index($readslices->[-2], $_) > -1 } @$reademail1;
                last unless index($lowercased, '@')  >  1;  # Must contain "@"
                last unless index($lowercased, '.')  >  1;  # Must contain "."
                last unless index($lowercased, '$') == -1;
                $hasmatched = 3;
                last;
            }

            if( $hasmatched > 0 && index($lowercased, '@') > 0 ) {
                # May be an email address
                my $w = [split(' ', $e)];
                my $x = $b->{'recipient'} || '';
                my $y = '';

                for my $ee ( @$w ) {
                    # Find an email address (including "@")
                    next unless index($ee, '@') > 1;
                    $y = Sisimai::Address->s3s4($ee);
                    next unless Sisimai::Address->is_emailaddress($y);
                    last;
                }

                if( $x && $x ne $y ) {
                    # There are multiple recipient addresses in the message body.
                    push @$dscontents, Sisimai::Lhost->DELIVERYSTATUS;
                    $b = $dscontents->[-1];
                }
                $b->{'recipient'} = $y;
                $recipients++;
                $itisbounce ||= 1;

            } elsif( $e =~ /[(](?:expanded|generated)[ ]from:?[ ]([^@]+[@][^@]+)[)]/ ) {
                # (expanded from: neko@example.jp)
                $b->{'alias'} = Sisimai::Address->s3s4($1);
            }
            $b->{'diagnosis'} .= ' '.$e;
        }
    } # END OF BODY_PARSER_FOR_FALLBACK
    return undef unless $itisbounce;

    if( $recipients == 0 && $rfc822text =~ /^To:[ ]*(.+)/m ) {
        # Try to get a recipient address from "To:" header of the original message
        if( my $r = Sisimai::Address->find($1, 1) ) {
            # Found a recipient address
            push @$dscontents, Sisimai::Lhost->DELIVERYSTATUS if scalar(@$dscontents) == $recipients;
            my $b = $dscontents->[-1];
            $b->{'recipient'} = $r->[0]->{'address'};
            $recipients++;
        }
    }
    return undef unless $recipients;

    require Sisimai::SMTP::Command;
    require Sisimai::MDA;
    my $mdabounced = Sisimai::MDA->inquire($mhead, $mbody);
    for my $e ( @$dscontents ) {
        # Set default values if each value is empty.
        $e->{ $_ } ||= $connheader->{ $_ } || '' for keys %$connheader;

        if( exists $e->{'alterrors'} && $e->{'alterrors'} ) {
            # Copy alternative error message
            $e->{'diagnosis'} ||= $e->{'alterrors'};
            if( index($e->{'diagnosis'}, '-') == 0 || substr($e->{'diagnosis'}, -2, 2) eq '__') {
                # Override the value of diagnostic code message
                $e->{'diagnosis'} = $e->{'alterrors'} if $e->{'alterrors'};
            }
            delete $e->{'alterrors'};
        }
        $e->{'diagnosis'} = Sisimai::String->sweep($e->{'diagnosis'});

        if( $mdabounced ) {
            # Make bounce data by the values returned from Sisimai::MDA->inquire()
            $e->{'agent'}     = $mdabounced->{'mda'} || 'RFC3464';
            $e->{'reason'}    = $mdabounced->{'reason'} || 'undefined';
            $e->{'diagnosis'} = $mdabounced->{'message'} if $mdabounced->{'message'};
            $e->{'command'}   = '';
        }
        $e->{'date'}    ||= $mhead->{'date'};
        $e->{'status'}  ||= Sisimai::SMTP::Status->find($e->{'diagnosis'}) || '';
        $e->{'command'} ||= $1 if $e->{'diagnosis'} =~ $markingsof->{'command'};
        $e->{'command'} ||= Sisimai::SMTP::Command->find($e->{'diagnosis'});
    }
    return { 'ds' => $dscontents, 'rfc822' => $rfc822text };
}

1;
__END__
=encoding utf-8

=head1 NAME

Sisimai::RFC3464 - bounce mail parser class for Fallback.

=head1 SYNOPSIS

    use Sisimai::RFC3464;

=head1 DESCRIPTION

Sisimai::RFC3464 is a class which called from called from only Sisimai::Message when other 
Sisimai::Lhost::* modules did not detected a bounce reason.

=head1 CLASS METHODS

=head2 C<B<description()>>

C<description()> returns description string of this module.

    print Sisimai::RFC3464->description;

=head2 C<B<inquire(I<header data>, I<reference to body string>)>>

C<inquire()> method parses a bounced email and return results as a array reference. See Sisimai::Message
for more details.

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2014-2022 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut
