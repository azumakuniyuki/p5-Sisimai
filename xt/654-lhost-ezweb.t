use strict;
use warnings;
use Test::More;
use lib qw(./lib ./blib/lib);
require './t/600-lhost-code';

my $enginename = 'EZweb';
my $samplepath = sprintf("./set-of-emails/private/lhost-%s", lc $enginename);
my $enginetest = Sisimai::Lhost::Code->makeinquiry;
my $isexpected = {
    # INDEX => [['D.S.N.', 'replycode', 'REASON', 'hardbounce'], [...]]
    '1001'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1002'  => [['5.0.910', '',    'filtered',        0]],
    '1003'  => [['5.0.911', '550', 'userunknown',     1]],
    '1004'  => [['5.0.911', '',    'userunknown',     1]],
    '1005'  => [['5.0.921', '',    'suspend',         0]],
    '1006'  => [['5.0.910', '',    'filtered',        0]],
    '1007'  => [['5.0.921', '',    'suspend',         0]],
    '1008'  => [['5.0.910', '',    'filtered',        0]],
    '1009'  => [['5.0.910', '',    'filtered',        0]],
    '1010'  => [['5.0.910', '',    'filtered',        0]],
    '1011'  => [['5.0.910', '',    'filtered',        0]],
    '1012'  => [['5.0.910', '',    'filtered',        0]],
    '1013'  => [['5.0.947', '',    'expired',         0]],
    '1014'  => [['5.0.910', '',    'filtered',        0]],
    '1015'  => [['5.0.921', '',    'suspend',         0]],
    '1016'  => [['5.0.910', '',    'filtered',        0]],
    '1017'  => [['5.0.910', '',    'filtered',        0]],
    '1018'  => [['5.0.910', '',    'filtered',        0]],
    '1019'  => [['5.0.0',   '550', 'suspend',         0]],
    '1020'  => [['5.0.910', '',    'filtered',        0]],
    '1021'  => [['5.0.910', '',    'filtered',        0]],
    '1022'  => [['5.0.910', '',    'filtered',        0]],
    '1023'  => [['5.0.921', '',    'suspend',         0]],
    '1024'  => [['5.0.910', '',    'filtered',        0]],
    '1025'  => [['5.0.910', '',    'filtered',        0]],
    '1026'  => [['5.0.910', '',    'filtered',        0]],
    '1027'  => [['5.0.910', '',    'filtered',        0]],
    '1028'  => [['5.0.910', '',    'filtered',        0]],
    '1029'  => [['5.0.0',   '550', 'suspend',         0]],
    '1030'  => [['5.0.910', '',    'filtered',        0]],
    '1031'  => [['5.0.921', '',    'suspend',         0]],
    '1032'  => [['5.0.910', '',    'filtered',        0]],
    '1033'  => [['4.0.922', '',    'mailboxfull',     0]],
    '1034'  => [['5.0.910', '',    'filtered',        0]],
    '1035'  => [['5.0.921', '',    'suspend',         0]],
    '1036'  => [['4.0.922', '',    'mailboxfull',     0]],
    '1037'  => [['5.0.911', '550', 'userunknown',     1]],
    '1038'  => [['5.0.921', '',    'suspend',         0]],
    '1039'  => [['5.0.921', '',    'suspend',         0]],
    '1040'  => [['5.0.921', '',    'suspend',         0]],
    '1041'  => [['5.0.0',   '550', 'suspend',         0]],
    '1042'  => [['5.0.921', '',    'suspend',         0]],
    '1043'  => [['5.0.921', '',    'suspend',         0]],
    '1044'  => [['5.0.911', '',    'userunknown',     1]],
    '1045'  => [['5.0.910', '',    'filtered',        0]],
    '1046'  => [['5.0.910', '',    'filtered',        0]],
    '1047'  => [['5.0.910', '',    'filtered',        0]],
    '1048'  => [['5.0.921', '',    'suspend',         0]],
    '1049'  => [['5.0.910', '',    'filtered',        0]],
    '1050'  => [['5.0.921', '',    'suspend',         0]],
    '1051'  => [['5.0.910', '',    'filtered',        0]],
    '1052'  => [['5.0.0',   '550', 'suspend',         0]],
    '1053'  => [['5.0.910', '',    'filtered',        0]],
    '1054'  => [['5.0.921', '',    'suspend',         0]],
    '1055'  => [['5.0.910', '',    'filtered',        0]],
    '1056'  => [['5.0.911', '',    'userunknown',     1]],
    '1057'  => [['5.0.910', '',    'filtered',        0]],
    '1058'  => [['5.0.0',   '550', 'suspend',         0]],
    '1059'  => [['5.0.921', '',    'suspend',         0]],
    '1060'  => [['5.0.910', '',    'filtered',        0]],
    '1061'  => [['5.0.921', '',    'suspend',         0]],
    '1062'  => [['5.0.910', '',    'filtered',        0]],
    '1063'  => [['5.0.911', '550', 'userunknown',     1]],
    '1064'  => [['5.0.910', '',    'filtered',        0]],
    '1065'  => [['5.0.921', '',    'suspend',         0]],
    '1066'  => [['5.0.910', '',    'filtered',        0]],
    '1067'  => [['5.0.910', '',    'filtered',        0]],
    '1068'  => [['5.0.0',   '550', 'suspend',         0]],
    '1069'  => [['5.0.921', '',    'suspend',         0]],
    '1070'  => [['5.0.921', '',    'suspend',         0]],
    '1071'  => [['5.0.910', '',    'filtered',        0]],
    '1072'  => [['5.0.921', '',    'suspend',         0]],
    '1073'  => [['5.0.910', '',    'filtered',        0]],
    '1074'  => [['5.0.910', '',    'filtered',        0]],
    '1075'  => [['5.0.921', '',    'suspend',         0]],
    '1076'  => [['5.0.910', '',    'filtered',        0]],
    '1077'  => [['5.0.947', '',    'expired',         0]],
    '1078'  => [['5.0.910', '',    'filtered',        0]],
    '1079'  => [['5.0.910', '',    'filtered',        0]],
    '1080'  => [['5.0.910', '',    'filtered',        0]],
    '1081'  => [['5.0.910', '',    'filtered',        0]],
    '1082'  => [['5.0.910', '',    'filtered',        0]],
    '1083'  => [['5.0.910', '',    'filtered',        0]],
    '1084'  => [['5.0.910', '',    'filtered',        0]],
    '1085'  => [['5.0.947', '',    'expired',         0]],
    '1086'  => [['5.0.910', '',    'filtered',        0]],
    '1087'  => [['5.0.910', '',    'filtered',        0]],
    '1089'  => [['5.0.910', '',    'filtered',        0]],
    '1090'  => [['5.0.0',   '550', 'suspend',         0]],
    '1091'  => [['5.0.910', '',    'filtered',        0]],
    '1092'  => [['5.0.910', '',    'filtered',        0]],
    '1093'  => [['5.0.921', '',    'suspend',         0]],
    '1094'  => [['5.0.911', '',    'userunknown',     1]],
    '1095'  => [['5.0.910', '',    'filtered',        0]],
    '1096'  => [['5.0.910', '',    'filtered',        0]],
    '1097'  => [['5.0.910', '',    'filtered',        0]],
    '1098'  => [['5.0.0',   '550', 'suspend',         0]],
    '1099'  => [['5.0.910', '',    'filtered',        0]],
    '1100'  => [['5.0.910', '',    'filtered',        0]],
    '1101'  => [['5.0.910', '',    'filtered',        0]],
    '1102'  => [['5.0.0',   '',    'suspend',         0]],
    '1103'  => [['5.0.911', '550', 'userunknown',     1]],
    '1104'  => [['5.0.910', '',    'filtered',        0]],
    '1105'  => [['5.0.910', '',    'filtered',        0]],
    '1106'  => [['5.0.911', '550', 'userunknown',     1]],
    '1107'  => [['5.0.910', '',    'filtered',        0]],
    '1108'  => [['5.7.1',   '553', 'norelaying',      0]],
    '1109'  => [['5.7.1',   '553', 'userunknown',     1]],
    '1110'  => [['5.0.910', '',    'filtered',        0]],
    '1111'  => [['5.0.0',   '550', 'suspend',         0]],
    '1112'  => [['5.0.921', '',    'suspend',         0]],
    '1113'  => [['5.0.921', '',    'suspend',         0]],
    '1114'  => [['5.0.910', '',    'filtered',        0]],
    '1115'  => [['5.0.0',   '',    'suspend',         0]],
    '1116'  => [['5.0.910', '',    'filtered',        0]],
    '1118'  => [['5.0.921', '',    'suspend',         0]],
    '1119'  => [['5.0.910', '',    'filtered',        0]],
    '1120'  => [['5.0.911', '550', 'userunknown',     1]],
    '1121'  => [['5.0.971', '550', 'blocked',         0]],
};

plan 'skip_all', sprintf("%s not found", $samplepath) unless -d $samplepath;
$enginetest->($enginename, $isexpected, 1, 0);
done_testing;

