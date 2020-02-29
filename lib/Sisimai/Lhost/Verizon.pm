package Sisimai::Lhost::Verizon;
use parent 'Sisimai::Lhost';
use feature ':5.10';
use strict;
use warnings;

state $Indicators = __PACKAGE__->INDICATORS;
my    $ReBackbone = qr/__BOUNDARY_STRING_HERE__/m;

sub description { 'Verizon Wireless: https://www.verizonwireless.com' }
sub make {
    # Detect an error from Verizon
    # @param         [Hash] mhead       Message headers of a bounce email
    # @options mhead [String] from      From header
    # @options mhead [String] date      Date header
    # @options mhead [String] subject   Subject header
    # @options mhead [Array]  received  Received headers
    # @options mhead [String] others    Other required headers
    # @param         [String] mbody     Message body of a bounce email
    # @return        [Hash, Undef]      Bounce data list and message/rfc822 part
    #                                   or Undef if it failed to parse or the
    #                                   arguments are missing
    # @since v4.0.0
    my $class = shift;
    my $mhead = shift // return undef;
    my $mbody = shift // return undef;
    my $match = -1;

    while(1) {
        # Check the value of "From" header
        # 'subject' => qr/Undeliverable Message/,
        last unless grep { rindex($_, '.vtext.com (') > -1 } @{ $mhead->{'received'} };
        $match = 1 if $mhead->{'from'} eq 'post_master@vtext.com';
        $match = 0 if $mhead->{'from'} =~ /[<]?sysadmin[@].+[.]vzwpix[.]com[>]?\z/;
        last;
    }
    return undef if $match < 0;

    my $dscontents = [__PACKAGE__->DELIVERYSTATUS];
    my $emailsteak = [];
    my $readcursor = 0;     # (Integer) Points the current cursor position
    my $recipients = 0;     # (Integer) The number of 'Final-Recipient' header
    my $senderaddr = '';    # (String) Sender address in the message body
    my $subjecttxt = '';    # (String) Subject of the original message

    my $StartingOf = {};    # (Ref->Hash) Delimiter strings
    my $MarkingsOf = {};    # (Ref->Hash) Delimiter patterns
    my $MessagesOf = {};    # (Ref->Hash) Error message patterns
    my $v = undef;

    if( $match == 1 ) {
        # vtext.com
        $MarkingsOf = { 'message' => qr/\AError:[ \t]/ };
        $MessagesOf = {
            # The attempted recipient address does not exist.
            'userunknown' => ['550 - Requested action not taken: no such user here'],
        };

        if( my $boundary00 = Sisimai::MIME->boundary($mhead->{'content-type'}) ) {
            # Convert to regular expression
            $boundary00 = '--'.$boundary00.'--';
            $ReBackbone = qr/^\Q$boundary00\E/m;
        }

        $emailsteak = Sisimai::RFC5322->fillet($mbody, $ReBackbone);
        for my $e ( split("\n", $emailsteak->[0]) ) {
            # Read error messages and delivery status lines from the head of the email
            # to the previous line of the beginning of the original message.
            unless( $readcursor ) {
                # Beginning of the bounce message or delivery status part
                $readcursor |= $Indicators->{'deliverystatus'} if $e =~ $MarkingsOf->{'message'};
                next;
            }
            next unless $readcursor & $Indicators->{'deliverystatus'};
            next unless length $e;

            # Message details:
            #   Subject: Test message
            #   Sent date: Wed Jun 12 02:21:53 GMT 2013
            #   MAIL FROM: *******@hg.example.com
            #   RCPT TO: *****@vtext.com
            $v = $dscontents->[-1];

            if( $e =~ /\A[ \t]+RCPT TO: (.*)\z/ ) {
                if( $v->{'recipient'} ) {
                    # There are multiple recipient addresses in the message body.
                    push @$dscontents, __PACKAGE__->DELIVERYSTATUS;
                    $v = $dscontents->[-1];
                }
                $v->{'recipient'} = $1;
                $recipients++;
                next;

            } elsif( $e =~ /\A[ \t]+MAIL FROM:[ \t](.+)\z/ ) {
                #   MAIL FROM: *******@hg.example.com
                $senderaddr ||= $1;

            } elsif( $e =~ /\A[ \t]+Subject:[ \t](.+)\z/ ) {
                #   Subject:
                $subjecttxt ||= $1;

            } else {
                # 550 - Requested action not taken: no such user here
                $v->{'diagnosis'} = $e if $e =~ /\A(\d{3})[ \t][-][ \t](.*)\z/;
            }
        }
    } else {
        # vzwpix.com
        $StartingOf = { 'message' => ['Message could not be delivered to mobile'] };
        $MessagesOf = { 'userunknown' => ['No valid recipients for this MM'] };

        if( my $boundary00 = Sisimai::MIME->boundary($mhead->{'content-type'}) ) {
            # Convert to regular expression
            $boundary00 = '--'.$boundary00.'--';
            $ReBackbone = qr/^\Q$boundary00\E/m;
        }

        $emailsteak = Sisimai::RFC5322->fillet($mbody, $ReBackbone);
        for my $e ( split("\n", $emailsteak->[0]) ) {
            # Read error messages and delivery status lines from the head of the email
            # to the previous line of the beginning of the original message.
            unless( $readcursor ) {
                # Beginning of the bounce message or delivery status part
                $readcursor |= $Indicators->{'deliverystatus'} if index($e, $StartingOf->{'message'}->[0]) == 0;
                next;
            }
            next unless $readcursor & $Indicators->{'deliverystatus'};
            next unless length $e;

            # Original Message:
            # From: kijitora <kijitora@example.jp>
            # To: 0000000000@vzwpix.com
            # Subject: test for bounce
            # Date:  Wed, 20 Jun 2013 10:29:52 +0000
            $v = $dscontents->[-1];

            if( $e =~ /\ATo:[ \t]+(.*)\z/ ) {
                if( $v->{'recipient'} ) {
                    # There are multiple recipient addresses in the message body.
                    push @$dscontents, __PACKAGE__->DELIVERYSTATUS;
                    $v = $dscontents->[-1];
                }
                $v->{'recipient'} = Sisimai::Address->s3s4($1);
                $recipients++;
                next;

            } elsif( $e =~ /\AFrom:[ \t](.+)\z/ ) {
                # From: kijitora <kijitora@example.jp>
                $senderaddr ||= Sisimai::Address->s3s4($1);

            } elsif( $e =~ /\ASubject:[ \t](.+)\z/ ) {
                #   Subject:
                $subjecttxt ||= $1;

            } else {
                # Message could not be delivered to mobile.
                # Error: No valid recipients for this MM
                $v->{'diagnosis'} = $e if $e =~ /\AError:[ \t]+(.+)\z/;
            }
        }
    }
    return undef unless $recipients;

    # Set the value of "MAIL FROM:" and "From:"
    $emailsteak->[1] .= sprintf("From: %s\n", $senderaddr) unless $emailsteak->[1] =~ /^From: /m;
    $emailsteak->[1] .= sprintf("Subject: %s\n", $subjecttxt) unless $emailsteak->[1] =~ /^Subject: /m;

    for my $e ( @$dscontents ) {
        $e->{'diagnosis'} = Sisimai::String->sweep($e->{'diagnosis'});

        SESSION: for my $r ( keys %$MessagesOf ) {
            # Verify each regular expression of session errors
            next unless grep { index($e->{'diagnosis'}, $_) > -1 } @{ $MessagesOf->{ $r } };
            $e->{'reason'} = $r;
            last;
        }
    }
    return { 'ds' => $dscontents, 'rfc822' => $emailsteak->[1] };
}

1;
__END__

=encoding utf-8

=head1 NAME

Sisimai::Lhost::Verizon - bounce mail parser class for C<Verizon Wireless>.

=head1 SYNOPSIS

    use Sisimai::Lhost::Verizon;

=head1 DESCRIPTION

Sisimai::Lhost::Verizon parses a bounce email which created by C<Verizon Wireless>.
Methods in the module are called from only Sisimai::Message.

=head1 CLASS METHODS

=head2 C<B<description()>>

C<description()> returns description string of this module.

    print Sisimai::Lhost::Verizon->description;

=head2 C<B<make(I<header data>, I<reference to body string>)>>

C<make()> method parses a bounced email and return results as a array reference.
See Sisimai::Message for more details.

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2014-2020 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut

