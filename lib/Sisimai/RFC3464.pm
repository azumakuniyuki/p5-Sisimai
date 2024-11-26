package Sisimai::RFC3464;
use v5.26;
use strict;
use warnings;
use Sisimai::Lhost;

# http://tools.ietf.org/html/rfc3464
sub description { 'RFC3464' };
sub inquire {
    # Detect an error for RFC3464
    # @param    [Hash] mhead    Message headers of a bounce email
    # @param    [String] mbody  Message body of a bounce email
    # @return   [Hash]          Bounce data list and message/rfc822 part
    # @return   [undef]         failed to decode or the arguments are missing
    my $class = shift;
    my $mhead = shift // return undef; return undef unless keys %$mhead;
    my $mbody = shift // return undef; return undef unless ref $mbody eq 'SCALAR';

    require Sisimai::RFC1894;
    require Sisimai::RFC2045;
    require Sisimai::RFC5322;
    require Sisimai::String;

    state $indicators = Sisimai::Lhost->INDICATORS;
    state $boundaries = [
        "Content-Type: message/rfc822",
        "Content-Type: text/rfc822-headers",
        "Content-Type: message/partial",
        "Content-Disposition: inline", # See lhost-amavis-*.eml, lhost-facebook-*.eml
    ];
    state $startingof = {"message" => ["Content-Type: message/delivery-status"]};
    state $fieldtable = Sisimai::RFC1894->FIELDTABLE;

    unless Sisimai::String->aligned($mbody, $boundaries) {
        # There is no "Content-Type: message/rfc822" line in the message body
        # Insert "Content-Type: message/rfc822" before "Return-Path:" of the original message
        my $p0 = index($$mbody, "\n\nReturn-Path:");
        $$mbody = sprintf("%s%s%s", substr($$mbody, 0, $p0), $boundaries->[0], substr($$mbody, $p0 + 1,)) if $p0 > 0;
    }

    my $permessage = {};
    my $dscontents = [Sisimai::Lhost->DELIVERYSTATUS];
    my $emailparts = Sisimai::RFC5322->part($mbody, $boundaries);
    my $readcursor = 0;     # (Integer) Points the current cursor position
    my $recipients = 0;     # (Integer) The number of 'Final-Recipient' header
    my $beforemesg = "";    # (String) String before $startingof->{"message"}
    my $goestonext = 0;     # (Bool) Flag: do not append the line into $beforemesg
    my $isboundary = [Sisimai::RFC2045->boundary($mhead->{"content-type"}, 0)];
    my $v = undef;
    my $p = "";

    while(index($emailparts->[0], '@') < 0) {
        # There is a bounce message inside of message/rfc822 part at lhost-x5-*
        my $p0 = index($$mbody, $boundaries->[0]."\n"); last if $p0 < 0;
        my $bo = substr($$mbody, $p0 + 32,);
        my $he = 1;
        my $cv = "";
        for my $e (split("\n", $bo)) {
            # Remove headers before the first "\n\n" after "Content-Type: message/rfc822" line
            if $he { if $e eq "" { $he = 0; next }} 
            next if index($e, "--") == 0;
            $cv .= $e."\n"
        }
        $emailparts = Sisimai::RFC5322->part(\$cv, $boundaries, 0);
        last;
    }

    if( index($emailparts->[0], $startingof->{"message"}->[0]) < 0 ) {
        # There is no "Content-Type: message/delivery-status" line in the message body
        # Insert "Content-Type: message/delivery-status" before "Reporting-MTA:" field
        my $cv = "\n\nReporting-MTA:";
        my $e0 = $emailparts->[0];
        my $p0 = index($e0, $cv);
        $emailparts->[0] = sprintf("%s\n\n%s%s", substr($e0, 0, $p0) $startingof->{"message"}->[0], substr($e0, p0,)) if $p0 > 0;
    }

    for my $e ( split("\n", $emailparts->[0]) ) {
        # Read error messages and delivery status lines from the head of the email to the previous
        # line of the beginning of the original message.
        if( $readcursor == 0 ) {
            # Beginning of the bounce message or message/delivery-status part
            $readcursor |= $indicators->{'deliverystatus'} if index($e, $startingof->{'message'}->[0]) == 0;

            while(1) {
                # Append each string before startingof["message"][0] except the following patterns
                # for the later reference
                last if $e eq "";       # Blank line
                last if $goestonext;    # Skip if the part is text/html, image/icon, in multipart/*

                # This line is a boundary kept in "multiparts" as a string, when the end of the boundary
                # appeared, the condition above also returns true.
                if( grep { index($e, $_) == 0 } @$isboundary ) { $goestonext = 0; last }
                if( index($e, "Content-Type:") == 0 ) {
                    # Content-Type: field in multipart/*
                    if( index($e, "multipart/") > 0 ) {
                        # Content-Type: multipart/alternative; boundary=aa00220022222222ffeebb
                        # Pick the boundary string and store it into "isboucdary"
                        push @$isboundary, Sisimai::RFC2045->boundary(e, 0);

                    } elsif( index($e, "text/plain") ) {
                        # Content-Type: "text/plain"
                        $goestonext = 0;

                    } else {
                        # Other types: for example, text/html, image/jpg, and so on
                        $goestonext = 1;
                    }
                    last;
                }

                last if index($e, "Content-") == 0;            # Content-Disposition, ...
                last if index($e, "This is a MIME") == 0;      # This is a MIME-formatted message.
                last if index($e, "This is a multi") == 0;     # This is a multipart message in MIME format
                last if index($e, "This is an auto") == 0;     # This is an automatically generated ...
                last if index($e, "This multi-part") == 0;     # This multi-part MIME message contains...
                last if index($e, "###") == 0;                 # A frame like #####
                last if index($e, "***") == 0;                 # A frame like *****
                last if index($e, "---- The follow") > -1;     # ----- The following addresses had delivery problems -----
                last if index($e, "---- Transcript") > -1;     # ----- Transcript of session follows -----
                $beforemesg .= $e." "; last;
            }
            next;
        }
        next unless $readcursor & $indicators->{'deliverystatus'};
        next unless length $e;

        if( my $f = Sisimai::RFC1894->match($e) ) {
            # $e matched with any field defined in RFC3464
            next unless my $o = Sisimai::RFC1894->field($e);
            $v = $dscontents->[-1];

            if( $o->[3] eq "addr" ) {
                # Final-Recipient: rfc822; kijitora@example.jp
                # X-Actual-Recipient: rfc822; kijitora@example.co.jp
                if( $o->[0] eq "final-recipient" ) {
                    # Final-Recipient: rfc822; kijitora@example.jp
                    # Final-Recipient: x400; /PN=...
                    my $cv = Sisimai::Address->s3s3($o->[2]); next unless Sisimai::Address->is_emailaddress($cv);
                    my $cw = scalar @$dscontents; next if $cw > 0 && $cv eq $dscontents->[$cw - 1]->{'recipient'};

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
            } elsif( $o->[3] eq "code" ) {
                # Diagnostic-Code: SMTP; 550 5.1.1 <userunknown@example.jp>... User Unknown
                $v->{'spec'}       = $o->[1];
                $v->{'diagnosis'} .= $o->[2]." ";

            } else {
                # Other DSN fields defined in RFC3464
                if( $o->[4] ne "" ) {
                    # There are other error messages as a comment such as the following:
                    # Status: 5.0.0 (permanent failure)
                    # Status: 4.0.0 (cat.example.net: host name lookup failure)
                    $v->{'diagnosis'} .= " ".$o->[4];
                }
                next unless exists $fieldtable->{ $o->[0] };
                $v->{ $fieldtable->{ $o->[0] } } = $o->[2];

                next unless $f == 1;
                $permessage->{ $fieldtable->{ $o->[0] } } = $o->[2];
            }
        } else {
            # Check that the line is a continued line of the value of Diagnostic-Code: field or not
            if( index($e, "X-") == 0 && index($e, ": ") > 1 ) {
                # This line is a MTA-Specific fields begins with "X-"
            } else {
                # The line may be a continued line of the value of the Diagnostic-Code: field

            }

        }

    } continue {
        # Save the current line for the next loop
        $p = $e;
    }
    return undef unless $recipients;









    my $match = 0;


    state $startingof = {
        'message' => [
            'content-type: message/delivery-status',
            'content-type: message/disposition-notification',
            'content-type: message/xdelivery-status',
            'content-type: text/plain; charset=',
            'the original message was received at ',
            'this report relates to your message',
            'your message could not be delivered',
            'your message was not delivered to ',
            'your message was not delivered to the following recipients',
        ],
        'rfc822'  => [
            'content-type: message/rfc822',
            'content-type: text/rfc822-headers',
            'return-path: <'
        ],
    };

    require Sisimai::Address;
    require Sisimai::RFC1894;
    my $fieldtable = Sisimai::RFC1894->FIELDTABLE;
    my $permessage = {};    # (Hash) Store values of each Per-Message field

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
            if( grep { index($lowercased, $_) == 0 } $startingof->{'message'}->@* ) {
                $readcursor |= $indicators->{'deliverystatus'};
                next;
            }
        }

        unless( $readcursor & $indicators->{'message-rfc822'} ) {
            # Beginning of the original message part(message/rfc822)
            if( grep { $lowercased eq $_ } $startingof->{'rfc822'}->@* ) {
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
            if( my $f = Sisimai::RFC1894->match($e) ) {
                # $e matched with any field defined in RFC3464
                next unless my $o = Sisimai::RFC1894->field($e);

                if( $o->[-1] eq 'addr' ) {
                    # Final-Recipient: rfc822; kijitora@example.jp
                    # X-Actual-Recipient: rfc822; kijitora@example.co.jp
                    if( $o->[0] eq 'final-recipient' || $o->[0] eq 'original-recipient' ) {
                        # Final-Recipient: rfc822; kijitora@example.jp
                        if( $o->[0] eq 'original-recipient' ) {
                            # Original-Recipient: ...
                            $maybealias = $o->[2];

                        } else {
                            # Final-Recipient: ...
                            my $x = $v->{'recipient'} || '';
                            my $y = Sisimai::Address->s3s4($o->[2]);
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
                    } elsif( $o->[0] eq 'x-actual-recipient' ) {
                        # X-Actual-Recipient: RFC822; |IFS=' ' && exec procmail -f- || exit 75 ...
                        # X-Actual-Recipient: rfc822; kijitora@neko.example.jp
                        $v->{'alias'} = $o->[2] unless index($o->[2], ' ') > -1;
                    }
                } elsif( $o->[-1] eq 'code' ) {
                    # Diagnostic-Code: SMTP; 550 5.1.1 <userunknown@example.jp>... User Unknown
                    $v->{'spec'}      = $o->[1];
                    $v->{'diagnosis'} = $o->[2];

                } else {
                    # Other DSN fields defined in RFC3464
                    next unless exists $fieldtable->{ $o->[0] };
                    $v->{ $fieldtable->{ $o->[0] } } = $o->[2];

                    next unless $f == 1;
                    $permessage->{ $fieldtable->{ $o->[0] } } = $o->[2];
                }
            } else {
                # The line did not match with any fields defined in RFC3464
                if( index($e, 'Diagnostic-Code: ') == 0 && index($e, ';') < 0 ) {
                    # There is no value of "diagnostic-type" such as Diagnostic-Code: 554 ...
                    $v->{'diagnosis'} = substr($e, index($e, ' ') + 1,);

                } elsif( index($e, 'Status: ') == 0 && Sisimai::SMTP::Reply->find(substr($e, 8, 3)) ) {
                    # Status: 553 Exceeded maximum inbound message size
                    $v->{'alterrors'} = substr($e, 8,);

                } elsif( index($p, 'Diagnostic-Code:') == 0 && index($e, ' ') == 0 ) {
                    # Continued line of the value of Diagnostic-Code field
                    $v->{'diagnosis'} .= $e;
                    $e = 'Diagnostic-Code: '.$e;

                } else {
                    # Get error messages which is written in the message body directly
                    next if index($e, ' ') == 0;
                    next if index($e, ' ') == 0;
                    next if index($e, 'X') == 0;

                    my $cr = Sisimai::SMTP::Reply->find($e);
                    my $ca = Sisimai::Address->find($e) || [];
                    my $co = Sisimai::String->aligned(\$e, ['<', '@', '>']);

                    $v->{'alterrors'} .= ' '.$e if length $cr || (scalar @$ca && $co);
                }
            }
        } # End of message/delivery-status
    } continue {
        # Save the current line for the next loop
        $p = $e;
    }

    # ---------------------------------------------------------------------------------------------
    BODY_DECODER_FOR_FALLBACK: {
        # Fallback, decode the entire message body
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
            '   the postfix ',
            'a summary of the undelivered message you sent follows:',
            'the following is the error message',
            'the message that you sent was undeliverable to the following',
            'your message was not delivered to ',
        ];
        state $donotread0 = ['   -----', ' -----', '--', '|--', '*'];
        state $donotread1 = ['mail from:', 'message-id:', '  from: '];
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

            last if grep { index($lowercased, $_) == 0 } $startingof->{'rfc822'}->@*;
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

            } elsif( index($e, '(expanded from') > -1 || index($e, '(generated from') > -1 ) {
                # (expanded from: neko@example.jp)
                $b->{'alias'} = Sisimai::Address->s3s4(substr($e, rindex($e, ' ') + 1,));
            }
            $b->{'diagnosis'} .= ' '.$e;
        }
    } # END OF BODY_DECODER_FOR_FALLBACK
    return undef unless $itisbounce;

    my $p1 = index($rfc822text, "\nTo: ");
    my $p2 = index($rfc822text, "\n", $p1 + 6);
    if( $recipients == 0 && $p1 > 0 ) {
        # Try to get a recipient address from "To:" header of the original message
        if( my $r = Sisimai::Address->find(substr($rfc822text, $p1 + 5, $p2 - $p1 - 5), 1) ) {
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
        $e->{'command'} ||= Sisimai::SMTP::Command->find($e->{'diagnosis'});
    }
    return { 'ds' => $dscontents, 'rfc822' => $rfc822text };
}

1;

package RFC3464::ThirdParty;
state $ThirdParty = {
    #"Aol"     => ["X-Outbound-Mail-Relay-"], # X-Outbound-Mail-Relay-(Queue-ID|Sender)
    "PowerMTA" => ["X-PowerMTA-"],            # X-PowerMTA-(VirtualMTA|BounceCategory)
    #"Yandex"  => ["X-Yandex-"],              # X-Yandex-(Queue-ID|Sender)
};
sub is3rdparty {
    # is3rdparty() returns true if the argument is a line generated by a MTA which have fields defined
    # in RFC3464 inside of a bounce mail the MTA returns
    # @param    string argv1   A line of a bounce mail
    # @return   bool           The line indicates that a bounce mail generated by the 3rd party MTA
    my $class = shift;
    my $argv1 = shift || return undef;

}

sub returnedby {
    # returnedby() returns an MTA name of the 3rd party
    # @param    string argv1   A line of a bounce mail
    # @return   string         An MTA name of the 3rd party
    my $class = shift;
    my $argv1 = shift || return undef;

    return undef unless index($argv1, "X-") == 0;
    for my $e ( keys %$ThirdParty ) {
        # Does the argument include the 3rd party specific field?
        return $e if index($e, $ThirdParty->{ $e }->[0]) == 0;
    }
    return ""
}

sub xfield {
    # xfield() returns rfc1894.Field() compatible slice for the specific field of the 3rd party MTA
    # @param    string argv1  A line of the error message
    # @return   []            RFC1894->field() compatible array
    # @see      Sisimai::RFC1894
    my $class = shift;
    my $argv1 = shift || return [];
    my $party = __PACKAGE__->returnedby($argv1); return [] unless $party;
    # Call RFC3464::PowerMTA->inquire()
}
1;

package RFC3464::PowerMTA;
1;

__END__
=encoding utf-8

=head1 NAME

Sisimai::RFC3464 - bounce mail decoder class for Fallback.

=head1 SYNOPSIS

    use Sisimai::RFC3464;

=head1 DESCRIPTION

C<Sisimai::RFC3464> is a class which called from called from only C<Sisimai::Message> when other 
C<Sisimai::Lhost::*> modules did not detected a bounce reason.

=head1 CLASS METHODS

=head2 C<B<description()>>

C<description()> method returns the description string of this module.

    print Sisimai::RFC3464->description;

=head2 C<B<inquire(I<header data>, I<reference to body string>)>>

C<inquire()> method method decodes a bounced email and return results as an array reference.
See C<Sisimai::Message> for more details.

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2014-2024 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut

