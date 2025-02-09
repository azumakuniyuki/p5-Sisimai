use strict;
use warnings;
use Test::More;
use lib qw(./lib ./blib/lib);
require './t/600-lhost-code';

my $enginename = 'X4';
my $samplepath = sprintf("./set-of-emails/private/lhost-%s", lc $enginename);
my $enginetest = Sisimai::Lhost::Code->makeinquiry;
my $isexpected = {
    # INDEX => [['D.S.N.', 'replycode', 'REASON', 'hardbounce'], [...]]
    '1001'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1002'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1003'  => [['5.1.2',   '',    'hostunknown',     1]],
    '1004'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1005'  => [['5.0.911', '550', 'userunknown',     1]],
    '1006'  => [['5.1.1',   '',    'userunknown',     1]],
    '1007'  => [['5.0.911', '550', 'userunknown',     1]],
    '1008'  => [['5.0.921', '550', 'suspend',         0]],
    '1009'  => [['5.1.1',   '',    'userunknown',     1]],
    '1010'  => [['5.1.2',   '',    'hostunknown',     1]],
    '1011'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1012'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1013'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1014'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1015'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1016'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1018'  => [['5.1.1',   '',    'userunknown',     1]],
    '1019'  => [['5.0.911', '550', 'userunknown',     1]],
    '1020'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1022'  => [['5.1.1',   '',    'userunknown',     1]],
    '1023'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1024'  => [['5.0.922', '',    'mailboxfull',     0]],
    '1025'  => [['5.1.1',   '',    'userunknown',     1]],
    '1026'  => [['5.0.911', '550', 'userunknown',     1]],
    '1027'  => [['5.0.922', '',    'mailboxfull',     0]],
};

plan 'skip_all', sprintf("%s not found", $samplepath) unless -d $samplepath;
$enginetest->($enginename, $isexpected, 1, 0);
done_testing;

