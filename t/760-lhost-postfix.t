use strict;
use warnings;
use Test::More;
use lib qw(./lib ./blib/lib);
require './t/600-lhost-code';

my $enginename = 'Postfix';
my $enginetest = Sisimai::Lhost::Code->makeinquiry;
my $isexpected = {
    # INDEX => [['D.S.N.', 'replycode', 'REASON', 'hardbounce'], [...]]
    '01' => [['5.1.1',   '',    'mailererror',     0]],
    '02' => [['5.2.1',   '550', 'userunknown',     1],
             ['5.1.1',   '550', 'userunknown',     1]],
    '03' => [['5.0.0',   '550', 'filtered',        0]],
    '04' => [['5.1.1',   '550', 'userunknown',     1]],
    '05' => [['4.1.1',   '450', 'userunknown',     1]],
    '06' => [['5.4.4',   '',    'hostunknown',     1]],
    '07' => [['5.0.910', '550', 'filtered',        0]],
    '08' => [['4.4.1',   '',    'expired',         0]],
    '09' => [['4.3.2',   '452', 'toomanyconn',     0]],
    '10' => [['5.1.8',   '553', 'rejected',        0]],
    '11' => [['5.1.8',   '553', 'rejected',        0],
             ['5.1.8',   '553', 'rejected',        0]],
    '13' => [['5.2.1',   '550', 'userunknown',     1],
             ['5.2.2',   '550', 'mailboxfull',     0]],
    '14' => [['5.1.1',   '',    'userunknown',     1]],
    '15' => [['4.4.1',   '',    'expired',         0]],
    '16' => [['5.1.6',   '550', 'hasmoved',        1]],
    '17' => [['5.4.4',   '',    'networkerror',    0]],
    '28' => [['5.7.1',   '550', 'notcompliantrfc', 0]],
    '29' => [['5.7.1',   '550', 'notcompliantrfc', 0]],
    '30' => [['5.4.1',   '550', 'userunknown',     1]],
    '31' => [['5.1.1',   '550', 'userunknown',     1]],
    '32' => [['5.1.1',   '550', 'userunknown',     1]],
    '33' => [['5.1.1',   '550', 'userunknown',     1]],
    '34' => [['5.0.944', '',    'networkerror',    0]],
    '35' => [['5.0.0',   '550', 'filtered',        0]],
    '36' => [['5.0.0',   '550', 'userunknown',     1]],
    '37' => [['4.4.1',   '',    'expired',         0]],
    '38' => [['4.0.0',   '',    'blocked',         0]],
    '39' => [['5.6.0',   '554', 'spamdetected',    0]],
    '40' => [['4.0.0',   '451', 'systemerror',     0]],
    '41' => [['5.0.0',   '550', 'policyviolation', 0]],
    '42' => [['5.0.0',   '550', 'policyviolation', 0]],
    '43' => [['4.3.0',   '',    'mailererror',     0]],
    '44' => [['5.7.1',   '501', 'norelaying',      0]],
    '45' => [['4.3.0',   '',    'mailboxfull',     0]],
    '46' => [['5.0.0',   '550', 'userunknown',     1]],
    '47' => [['5.0.0',   '554', 'systemerror',     0]],
    '48' => [['5.0.0',   '552', 'toomanyconn',     0]],
    '49' => [['4.0.0',   '421', 'blocked',         0]],
    '50' => [['4.0.0',   '421', 'blocked',         0]],
    '51' => [['5.7.0',   '550', 'policyviolation', 0]],
    '52' => [['5.0.0',   '554', 'suspend',         0]],
    '53' => [['5.0.0',   '504', 'syntaxerror',     0]],
    '54' => [['5.7.1',   '550', 'rejected',        0]],
    '55' => [['5.0.0',   '552', 'toomanyconn',     0]],
    '56' => [['4.4.2',   '',    'networkerror',    0]],
    '57' => [['5.2.1',   '550', 'userunknown',     1]],
    '58' => [['5.7.1',   '550', 'badreputation',   0]],
    '59' => [['5.2.1',   '550', 'speeding',        0]],
    '60' => [['4.0.0',   '',    'requireptr',      0]],
    '61' => [['5.0.0',   '550', 'suspend',         0]],
    '62' => [['5.0.0',   '550', 'virusdetected',   0]],
    '63' => [['5.2.2',   '552', 'mailboxfull',     0]],
    '64' => [['5.0.900', '',    'undefined',       0]],
    '65' => [['5.0.0',   '550', 'securityerror',   0]],
    '66' => [['5.7.9',   '554', 'policyviolation', 0]],
    '67' => [['5.7.9',   '554', 'policyviolation', 0]],
    '68' => [['5.0.0',   '554', 'policyviolation', 0]],
    '69' => [['5.7.9',   '554', 'policyviolation', 0]],
    '70' => [['5.7.26',  '550', 'authfailure',     0]],
    '71' => [['5.7.1',   '554', 'authfailure',     0]],
    '72' => [['5.7.1',   '550', 'authfailure',     0]],
    '73' => [['5.7.1',   '550', 'authfailure',     0]],
    '74' => [['4.7.0',   '421', 'rejected',        0]],
    '75' => [['4.3.0',   '451', 'systemerror',     0]],
    '76' => [['5.0.0',   '550', 'userunknown',     1]],
    '77' => [['5.0.0',   '554', 'norelaying',      0]],
    '78' => [['5.0.0',   '554', 'notcompliantrfc', 0]],
};

$enginetest->($enginename, $isexpected);
done_testing;

