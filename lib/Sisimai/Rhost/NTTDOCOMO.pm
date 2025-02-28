package Sisimai::Rhost::NTTDOCOMO;
use v5.26;
use strict;
use warnings;

sub find {
    # Detect bounce reason from NTT docomo
    # @param    [Sisimai::Fact] argvs   Decoded email object
    # @return   [String]                The bounce reason for docomo.ne.jp
    # @since v4.25.15
    my $class = shift;
    my $argvs = shift // return undef; return "" unless $argvs->{'diagnosticcode'};

    my $messagesof = {
        'mailboxfull' => ['552 too much mail data'],
        'syntaxerror' => ['503 bad sequence of commands', '504 command parameter not implemented'],
        'toomanyconn' => ['552 too many recipients'],
        'userunknown' => ['550 unknown user'],
    };
    my $statuscode = $argvs->{'deliverystatus'}    || '';
    my $thecommand = $argvs->{'command'}           || '';
    my $issuedcode = lc $argvs->{'diagnosticcode'} || '';
    my $reasontext = '';

    # Check the value of Status: field, an SMTP Reply Code, and the SMTP Command
    if( $statuscode eq '5.1.1' || $statuscode eq '5.0.911' ) {
        #    ----- Transcript of session follows -----
        # ... while talking to mfsmax.docomo.ne.jp.:
        # >>> RCPT To:<***@docomo.ne.jp>
        # <<< 550 Unknown user ***@docomo.ne.jp
        # 550 5.1.1 <***@docomo.ne.jp>... User unknown
        # >>> DATA
        # <<< 503 Bad sequence of commands
        $reasontext = 'userunknown';

    } elsif( $statuscode eq '5.2.0' ) {
        #    ----- The following addresses had permanent fatal errors -----
        # <***@docomo.ne.jp>
        # (reason: 550 Unknown user ***@docomo.ne.jp)
        # 
        #    ----- Transcript of session follows -----
        # ... while talking to mfsmax.docomo.ne.jp.:
        # >>> DATA
        # <<< 550 Unknown user ***@docomo.ne.jp
        # 554 5.0.0 Service unavailable
        # ...
        # Final-Recipient: RFC822; ***@docomo.ne.jp
        # Action: failed
        # Status: 5.2.0
        $reasontext = 'filtered';

    } else {
        # The value of "Diagnostic-Code:" field is not empty
        for my $e ( keys %$messagesof ) {
            # - The key name is a bounce reason name
            # - https://github.com/sisimai/go-sisimai/issues/64
            # - After March 12, 2025, if an error message contains "550 Unknown user", the
            #   bounce reason will be definitively "userunknown". This is because NTT DOCOMO
            #   no longer rejects emails via SMTP for domain-specific rejection or specified
            #   reception filters.
            next unless grep { index($issuedcode, $_) > -1 } $messagesof->{ $e }->@*;
            $reasontext = $e;
            last;
        }
    }
    return $reasontext if length $reasontext;

    # A bounce reason did not decide from a status code, an error message.
    if( $statuscode eq '5.0.0' ) {
        # Status: 5.0.0
        if( $thecommand eq 'RCPT' ) {
            # Your message to the following recipients cannot be delivered:
            #
            # <***@docomo.ne.jp>:
            # mfsmax.docomo.ne.jp [203.138.181.112]:
            # >>> RCPT TO:<***@docomo.ne.jp>
            # <<< 550 Unknown user ***@docomo.ne.jp
            # ...
            #
            # Final-Recipient: rfc822; ***@docomo.ne.jp
            # Action: failed
            # Status: 5.0.0
            # Remote-MTA: dns; mfsmax.docomo.ne.jp [203.138.181.112]
            # Diagnostic-Code: smtp; 550 Unknown user ***@docomo.ne.jp
            $reasontext = 'userunknown';

        } elsif( $thecommand eq 'DATA' ) {
            # <***@docomo.ne.jp>: host mfsmax.docomo.ne.jp[203.138.181.240] said:
            # 550 Unknown user ***@docomo.ne.jp (in reply to end of DATA
            # command)
            # ...
            # Final-Recipient: rfc822; ***@docomo.ne.jp
            # Original-Recipient: rfc822;***@docomo.ne.jp
            # Action: failed
            # Status: 5.0.0
            # Remote-MTA: dns; mfsmax.docomo.ne.jp
            # Diagnostic-Code: smtp; 550 Unknown user ***@docomo.ne.jp
            $reasontext = 'rejected';

        } else {
            # Rejected by other SMTP commands: AUTH, MAIL,
            #   もしもこのブロックを通過するNTTドコモからのエラーメッセージを見つけたら
            #   https://github.com/sisimai/p5-sisimai/issues からご連絡ねがいます。
            #
            #   If you found a error message from mfsmax.docomo.ne.jp which passes this block,
            #   please open an issue at https://github.com/sisimai/p5-sisimai/issues .
        }
    } else {
        # Status: field is neither 5.0.0 nor values defined in code above
        #   もしもこのブロックを通過するNTTドコモからのエラーメッセージを見つけたら
        #   https://github.com/sisimai/p5-sisimai/issues からご連絡ねがいます。
        #
        #   If you found a error message from mfsmax.docomo.ne.jp which passes this block,
        #   please open an issue at https://github.com/sisimai/p5-sisimai .
    }
    return $reasontext;
}

1;
__END__

=encoding utf-8

=head1 NAME

Sisimai::Rhost::NTTDOCOMO - Detect the bounce reason returned from NTT docomo.

=head1 SYNOPSIS

    use Sisimai::Rhost::NTTDOCOMO;

=head1 DESCRIPTION

C<Sisimai::Rhost::NTTDOCOMO> detects the bounce reason from the content of C<Sisimai::Fact> object
as an argument of C<find()> method when the value of C<rhost> of the object is C<mfsmax.docomo.ne.jp>.
This class is called only C<Sisimai::Fact> class.

=head1 CLASS METHODS

=head2 C<B<find(I<Sisimai::Fact Object>)>>

C<find()> method detects the bounce reason.

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2022-2025 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut

