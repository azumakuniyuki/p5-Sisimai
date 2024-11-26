package Sisimai::Test::Modules;
sub list {
    my $v = [];
    my $f = [ qw|
        Address.pm
        ARF.pm
        DateTime.pm
        Fact.pm
            Fact/JSON.pm
            Fact/YAML.pm
        Lhost.pm
            Lhost/Activehunter.pm
            Lhost/Amavis.pm
            Lhost/AmazonSES.pm
            Lhost/AmazonWorkMail.pm
            Lhost/Aol.pm
            Lhost/ApacheJames.pm
            Lhost/Barracuda.pm
            Lhost/Bigfoot.pm
            Lhost/Biglobe.pm
            Lhost/Courier.pm
            Lhost/Domino.pm
            Lhost/DragonFly.pm
            Lhost/EinsUndEins.pm
            Lhost/Exchange2003.pm
            Lhost/Exchange2007.pm
            Lhost/Exim.pm
            Lhost/EZweb.pm
            Lhost/Facebook.pm
            Lhost/FML.pm
            Lhost/GMX.pm
            Lhost/Gmail.pm
            Lhost/GoogleGroups.pm
            Lhost/GSuite.pm
            Lhost/IMailServer.pm
            Lhost/InterScanMSS.pm
            Lhost/KDDI.pm
            Lhost/MailFoundry.pm
            Lhost/MailMarshalSMTP.pm
            Lhost/MailRu.pm
            Lhost/McAfee.pm
            Lhost/MessageLabs.pm
            Lhost/MessagingServer.pm
            Lhost/mFILTER.pm
            Lhost/MXLogic.pm
            Lhost/Notes.pm
            Lhost/Office365.pm
            Lhost/OpenSMTPD.pm
            Lhost/Outlook.pm
            Lhost/Postfix.pm
            Lhost/PowerMTA.pm
            Lhost/qmail.pm
            Lhost/ReceivingSES.pm
            Lhost/SendGrid.pm
            Lhost/Sendmail.pm
            Lhost/SurfControl.pm
            Lhost/V5sendmail.pm
            Lhost/Verizon.pm
            Lhost/X1.pm
            Lhost/X2.pm
            Lhost/X3.pm
            Lhost/X4.pm
            Lhost/X5.pm
            Lhost/X6.pm
            Lhost/Yahoo.pm
            Lhost/Yandex.pm
            Lhost/Zoho.pm
        Mail.pm
            Mail/Mbox.pm
            Mail/Maildir.pm
            Mail/Memory.pm
            Mail/STDIN.pm
        Message.pm
        MDA.pm
        Order.pm
        Reason.pm
            Reason/AuthFailure.pm
            Reason/BadReputation.pm
            Reason/Blocked.pm
            Reason/ContentError.pm
            Reason/Delivered.pm
            Reason/ExceedLimit.pm
            Reason/Expired.pm
            Reason/Feedback.pm
            Reason/Filtered.pm
            Reason/HasMoved.pm
            Reason/HostUnknown.pm
            Reason/MailboxFull.pm
            Reason/MailerError.pm
            Reason/MesgTooBig.pm
            Reason/NoRelaying.pm
            Reason/NotAccept.pm
            Reason/NotCompliantRFC.pm
            Reason/NetworkError.pm
            Reason/OnHold.pm
            Reason/PolicyViolation.pm
            Reason/Rejected.pm
            Reason/RequirePTR.pm
            Reason/SecurityError.pm
            Reason/SpamDetected.pm
            Reason/Speeding.pm
            Reason/Suppressed.pm
            Reason/Suspend.pm
            Reason/SyntaxError.pm
            Reason/SystemError.pm
            Reason/SystemFull.pm
            Reason/TooManyConn.pm
            Reason/Undefined.pm
            Reason/UserUnknown.pm
            Reason/Vacation.pm
            Reason/VirusDetected.pm
        RFC1123.pm
        RFC1894.pm
        RFC2045.pm
        RFC3464.pm
            RFC3464/ThirdParty.pm
        RFC3834.pm
        RFC5322.pm
        RFC5965.pm
        Rhost.pm
            Rhost/Apple.pm
            Rhost/Cox.pm
            Rhost/FrancePTT.pm
            Rhost/GoDaddy.pm
            Rhost/Google.pm
            Rhost/IUA.pm
            Rhost/KDDI.pm
            Rhost/Microsoft.pm
            Rhost/Mimecast.pm
            Rhost/NTTDOCOMO.pm
            Rhost/Spectrum.pm
            Rhost/Tencent.pm
            Rhost/YahooInc.pm
        SMTP.pm
            SMTP/Command.pm
            SMTP/Failure.pm
            SMTP/Reply.pm
            SMTP/Status.pm
            SMTP/Transcript.pm
        String.pm
        Time.pm
    | ];

    push @$v, 'Sisimai.pm';
    for my $e ( @$f ) {
        push @$v, sprintf("Sisimai/%s", $e);
    }
    return $v;
}
1;
