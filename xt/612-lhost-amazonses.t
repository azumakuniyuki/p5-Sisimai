use strict;
use warnings;
use Test::More;
use lib qw(./lib ./blib/lib);
require './t/600-lhost-code';

my $enginename = 'AmazonSES';
my $samplepath = sprintf("./set-of-emails/private/lhost-%s", lc $enginename);
my $enginetest = Sisimai::Lhost::Code->makeinquiry;
my $isexpected = {
    # INDEX => [['D.S.N.', 'replycode', 'REASON', 'hardbounce'], [...]]
    '1001'  => [['5.2.2',   '550', 'mailboxfull',     0]],
    '1002'  => [['5.2.1',   '550', 'filtered',        0]],
    '1003'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1004'  => [['5.2.2',   '550', 'mailboxfull',     0]],
    '1005'  => [['5.7.1',   '550', 'securityerror',   0]],
    '1006'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1007'  => [['5.4.7',   '',    'expired',         0]],
    '1008'  => [['5.1.2',   '',    'hostunknown',     1]],
    '1009'  => [['5.1.0',   '550', 'userunknown',     1]],
    '1010'  => [['5.1.0',   '550', 'userunknown',     1]],
    '1011'  => [['5.1.0',   '550', 'userunknown',     1]],
    '1012'  => [['5.1.0',   '550', 'userunknown',     1]],
    '1013'  => [['5.1.0',   '550', 'userunknown',     1]],
    '1014'  => [['5.3.0',   '550', 'filtered',        0]],
    '1015'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1016'  => [['',        '',    'feedback',        0, 'abuse']],
    '1017'  => [['2.6.0',   '250', 'delivered',       0]],
    '1018'  => [['2.6.0',   '250', 'delivered',       0]],
    '1019'  => [['5.7.1',   '554', 'blocked',         0]],
    '1020'  => [['4.4.2',   '421', 'expired',         0]],
    '1021'  => [['5.4.4',   '550', 'hostunknown',     1]],
    '1022'  => [['5.5.1',   '550', 'blocked',         0]],
    '1023'  => [['5.7.1',   '550', 'suspend',         0]],
    '1024'  => [['5.4.1',   '550', 'userunknown',     1]],
    '1025'  => [['5.2.1',   '550', 'suspend',         0]],
    '1026'  => [['5.7.1',   '554', 'norelaying',      0]],
    '1027'  => [['5.2.2',   '552', 'mailboxfull',     0]],
    '1028'  => [['5.4.7',   '',    'expired',         0]],
    '1029'  => [['5.1.0',   '550', 'userunknown',     1]],
    '1030'  => [['2.6.0',   '250', 'delivered',       0]],
    '1031'  => [['2.6.0',   '250', 'delivered',       0]],
};

plan 'skip_all', sprintf("%s not found", $samplepath) unless -d $samplepath;
$enginetest->($enginename, $isexpected, 1, 0);
done_testing;

