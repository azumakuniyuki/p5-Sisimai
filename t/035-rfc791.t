use strict;
use Test::More;
use lib qw(./lib ./blib/lib);
use Sisimai::RFC791;

my $Package = 'Sisimai::RFC791';
my $Methods = {
    'class'  => ['is_ipv4address', 'find'],
    'object' => [],
};

use_ok $Package;
can_ok $Package, @{ $Methods->{'class'} };

MAKETEST: {
    is(Sisimai::RFC791->find('host smtp.example.jp 127.0.0.4 SMTP error from remote mail server')->[0], '127.0.0.4', '->find returns 127.0.0.4');
    is(Sisimai::RFC791->find('mx.example.jp (192.0.2.2) reason: 550 5.2.0 Mail rejete.')->[0], '192.0.2.2', '->find returns 192.0.2.2');
    is(Sisimai::RFC791->find('Client host [192.0.2.49] blocked using cbl.abuseat.org (state 13).')->[0], '192.0.2.49', '->find returns 192.0.2.49');
    is(Sisimai::RFC791->find('127.0.0.1')->[0], '127.0.0.1', '->find returns 127.0.0.1');
    is(Sisimai::RFC791->find('365.31.7.1')->[0], undef, '->find(365.31.7.1) returns undef');
    is(Sisimai::RFC791->find('a.b.c.d')->[0], undef, '->find(a.b.c.d) returns undef');
    is(Sisimai::RFC791->find(''), undef, '->find("") returns undef');
    is(Sisimai::RFC791->find('3.14')->@*, []->@*, '->find("3.15") returns []');

    my $addr0 = ["123.456.78.9"];
    my $addr1 = ["192.0.2.22"];
    for my $e ( @$addr0 ) {
        is(Sisimai::RFC791->is_ipv4address($e), 0, "->is_ipv4address(".$e.") returns 0");
    }
    for my $e ( @$addr1 ) {
        is(Sisimai::RFC791->is_ipv4address($e), 1, "->is_ipv4address(".$e.") returns 1");
    }
}

done_testing;

