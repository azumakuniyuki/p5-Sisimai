use strict;
use warnings;
use Test::More;
use lib qw(./lib ./blib/lib);
require './t/600-lhost-code';

my $enginename = 'Domino';
my $samplepath = sprintf("./set-of-emails/private/lhost-%s", lc $enginename);
my $enginetest = Sisimai::Lhost::Code->maketest;
my $isexpected = [
    { 'n' => '01001', 'r' => qr/onhold/      },
    { 'n' => '01002', 'r' => qr/userunknown/ },
    { 'n' => '01003', 'r' => qr/userunknown/ },
    { 'n' => '01004', 'r' => qr/userunknown/ },
    { 'n' => '01005', 'r' => qr/onhold/      },
    { 'n' => '01006', 'r' => qr/userunknown/ },
    { 'n' => '01007', 'r' => qr/userunknown/ },
    { 'n' => '01008', 'r' => qr/userunknown/ },
    { 'n' => '01009', 'r' => qr/userunknown/ },
    { 'n' => '01010', 'r' => qr/userunknown/ },
    { 'n' => '01011', 'r' => qr/userunknown/ },
    { 'n' => '01012', 'r' => qr/userunknown/ },
    { 'n' => '01013', 'r' => qr/userunknown/ },
#   { 'n' => '01014', 'r' => qr/userunknown/ },
    { 'n' => '01015', 'r' => qr/networkerror/},
    { 'n' => '01016', 'r' => qr/systemerror/ },
    { 'n' => '01017', 'r' => qr/userunknown/ },
];

plan 'skip_all', sprintf("%s not found", $samplepath) unless -d $samplepath;
$enginetest->($enginename, $isexpected, 1, 0);
done_testing;

