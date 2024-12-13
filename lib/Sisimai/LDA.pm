package Sisimai::LDA;
use v5.26;
use strict;
use warnings;

state $LocalAgent = {
    # Each error message should be a lower-cased string
    # dovecot/src/deliver/deliver.c
    # 11: #define DEFAULT_MAIL_REJECTION_HUMAN_REASON \
    # 12: "Your message to <%t> was automatically rejected:%n%r"
    "dovecot"    => ["Your message to ", " was automatically rejected:"],
    "mail.local" => ["mail.local: "],
    "procmail"   => ["procmail: ", "/procmail "],
    "maildrop"   => ["maildrop: "],
    "vpopmail"   => ["vdelivermail: "],
    "vmailmgr"   => ["vdeliver: "],
};

state $MessagesOf = {
    # Each error message should be a lower-cased string
    "dovecot" => {
        # dovecot/src/deliver/mail-send.c:94
        "mailboxfull" => [
            "not enough disk space",
            "quota exceeded",   # Dovecot 1.2 dovecot/src/plugins/quota/quota.c
            "quota exceeded (mailbox for user is full)",    # dovecot/src/plugins/quota/quota.c
        ],
        "userunknown" => ["mailbox doesn't exist: "],
    },
    "mail.local" => {
        "mailboxfull" => ["disc quota exceeded", "mailbox full or quota exceeded"],
        "systemerror" => ["temporary file write error"],
        "userunknown" => [
            ": invalid mailbox path",
            ": unknown user:",
            ": user missing home directory",
            ": user unknown",
        ],
    },
    "procmail" => {
        "mailboxfull" => ["quota exceeded while writing", "user over quota"],
        "systemerror" => ["service unavailable"],
        "systemfull"  => ["no space left to finish writing"],
    },
    "maildrop" => {
        "mailboxfull" => ["maildir over quota."],
        "userunknown" => ["invalid user specified.", "cannot find system user"],
    },
    "vpopmail" => {
        "filtered"    => ["user does not exist, but will deliver to "],
        "mailboxfull" => ["domain is over quota", "user is over quota"],
        "suspend"     => ["account is locked email bounced"],
        "userunknown" => ["sorry, no mailbox here by that name."],
    },
    "vmailmgr" => {
        "mailboxfull" => ["delivery failed due to system quota violation"],
        "userunknown" => [
            "invalid or unknown base user or domain",
            "invalid or unknown virtual user",
            "user name does not refer to a virtual user"
        ],
    },
};

sub find {
    # Decode the message body and return a bounce reason detected by the error message of LDA
    # @param    [Sisimai::Fact] argvs   Decoded email object
    # @return   [String]                The value of bounce reason
    my $class = shift;
    my $argvs = shift // return undef;

    return "" unless length $argvs->{"diagnosticcode"};
    return "" unless $argvs->{"smtpcommand"} eq "" || $argvs->{"smtpcommand"} eq "DATA";

    my $deliversby = "";    # [String] Local Delivery Agent name
    my $reasontext = "";    # [String] Detected bounce reason
    my $issuedcode = lc $argvs->{"diagnosticcode"};

    for my $e ( keys %$LocalAgent ) {
        # Find a local delivery agent name from the lower-cased error message
        next unless grep { index($issuedcode, $_) > -1 } $LocalAgent->{ $e }->@*;
        $deliversby = $e; last;
    }
    return "" unless $deliversby;

    for my $e ( keys $MessagesOf->{ $deliversby }->%* ) {
        # The key nane is a bounce reason name
        next unless grep { index($issuedcode, $_) > -1 } $MessagesOf->{ $deliversby }->{ $e }->@*;
        $reasontext = $e; last;
    }

    $reasontext ||= "mailererror"; # procmail: Couldn't create "/var/mail/tmp.nekochan.22"
    return $reasontext;
}

1;
__END__

=encoding utf-8

=head1 NAME

Sisimai::LDA - Error message decoder for LDA; Local Delivery Agent

=head1 SYNOPSIS

    use Sisimai::LDA;
    my $fact = Sisimai::Fact->rise($v);
    my $ldav = Sisimai::LDA->find($fact->[0]); # Returns the bounce reason LDA generated

=head1 DESCRIPTION

C<Sisimai::LDA> decodes bounced email which created by some LDA, such as Dovecot, C<mail.local>,
C<procmail>, and so on. This class is called from C<Sisimai::Fact> only.

=head1 CLASS METHODS

=head2 C<B<find(I<Sisimai::Fact Object>)>>

C<find()> method detects the bounce reason using the error message generated by LDA

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2014-2016,2018-2024 azumakuniyuki, All rights reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut

