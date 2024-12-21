use strict;
use warnings;
use Test::More;
use lib qw(./lib ./blib/lib);
require './t/600-lhost-code';

my $enginename = 'Exchange2007';
my $samplepath = sprintf("./set-of-emails/private/lhost-%s", lc $enginename);
my $enginetest = Sisimai::Lhost::Code->makeinquiry;
my $isexpected = {
    # INDEX => [['D.S.N.', 'replycode', 'REASON', 'hardbounce'], [...]]
    '1001'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1002'  => [['5.2.3',   '550', 'exceedlimit',     0]],
    '1003'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1004'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1005'  => [['5.2.2',   '550', 'mailboxfull',     0]],
    '1006'  => [['5.2.3',   '550', 'exceedlimit',     0]],
    '1007'  => [['5.2.2',   '550', 'mailboxfull',     0]],
    '1008'  => [['5.7.1',   '550', 'securityerror',   0]],
    '1009'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1010'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1011'  => [['5.2.3',   '550', 'exceedlimit',     0]],
    '1012'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1013'  => [['5.0.910', '550', 'filtered',        0]],
    '1014'  => [['4.2.0',   '',    'systemerror',     0]],
    '1015'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1016'  => [['5.2.3',   '550', 'exceedlimit',     0]],
    '1017'  => [['5.1.10',  '550', 'userunknown',     1]],
    '1018'  => [['5.1.10',  '550', 'userunknown',     1]],
};

plan 'skip_all', sprintf("%s not found", $samplepath) unless -d $samplepath;
$enginetest->($enginename, $isexpected, 1, 0);
done_testing;

