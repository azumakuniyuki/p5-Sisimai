use strict;
use warnings;
use Test::More;
use lib qw(./lib ./blib/lib);
require './t/600-lhost-code';

my $enginename = 'SendGrid';
my $samplepath = sprintf("./set-of-emails/private/lhost-%s", lc $enginename);
my $enginetest = Sisimai::Lhost::Code->makeinquiry;
my $isexpected = {
    # INDEX => [['D.S.N.', 'replycode', 'REASON', 'hardbounce'], [...]]
    '1001'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1002'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1003'  => [['5.0.947', '',    'expired',         0]],
    '1004'  => [['5.0.911', '550', 'userunknown',     1]],
    '1005'  => [['5.2.1',   '550', 'userunknown',     1]],
    '1006'  => [['5.2.2',   '550', 'mailboxfull',     0]],
    '1007'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1008'  => [['5.0.911', '554', 'userunknown',     1]],
    '1009'  => [['5.0.911', '550', 'userunknown',     1]],
};

plan 'skip_all', sprintf("%s not found", $samplepath) unless -d $samplepath;
$enginetest->($enginename, $isexpected, 1, 0);
done_testing;

