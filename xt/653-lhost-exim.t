use strict;
use warnings;
use Test::More;
use lib qw(./lib ./blib/lib);
require './t/600-lhost-code';

my $enginename = 'Exim';
my $samplepath = sprintf("./set-of-emails/private/lhost-%s", lc $enginename);
my $enginetest = Sisimai::Lhost::Code->makeinquiry;
my $isexpected = {
    # INDEX => [['D.S.N.', 'replycode', 'REASON', 'hardbounce'], [...]]
    '1001'  => [['5.7.0',   '554', 'policyviolation', 0]],
    '1002'  => [['4.0.947', '',    'expired',         0]],
    '1003'  => [['5.0.910', '',    'filtered',        0]],
    '1004'  => [['5.7.0',   '550', 'blocked',         0]],
    '1005'  => [['5.1.1',   '550', 'userunknown',     1],
                ['5.2.1',   '550', 'userunknown',     1]],
    '1006'  => [['5.0.910', '',    'filtered',        0]],
    '1007'  => [['5.7.0',   '554', 'policyviolation', 0]],
    '1008'  => [['5.0.911', '550', 'userunknown',     1]],
    '1009'  => [['5.0.912', '',    'hostunknown',     1]],
    '1010'  => [['5.7.0',   '550', 'blocked',         0]],
    '1011'  => [['5.1.1',   '553', 'userunknown',     1]],
    '1012'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1013'  => [['5.0.911', '550', 'userunknown',     1]],
    '1014'  => [['4.0.947', '',    'expired',         0]],
    '1015'  => [['4.0.947', '',    'expired',         0]],
    '1016'  => [['5.0.911', '550', 'userunknown',     1]],
    '1017'  => [['4.0.947', '',    'expired',         0]],
    '1018'  => [['5.0.911', '550', 'userunknown',     1]],
    '1019'  => [['5.1.1',   '553', 'userunknown',     1]],
    '1020'  => [['5.0.911', '550', 'userunknown',     1]],
    '1022'  => [['5.0.911', '550', 'userunknown',     1]],
    '1023'  => [['5.2.1',   '550', 'userunknown',     1]],
    '1024'  => [['5.0.911', '550', 'userunknown',     1]],
    '1025'  => [['5.0.911', '550', 'userunknown',     1]],
    '1026'  => [['5.0.911', '550', 'userunknown',     1]],
    '1027'  => [['4.0.947', '',    'expired',         0]],
    '1028'  => [['5.2.2',   '550', 'mailboxfull',     0]],
    '1029'  => [['5.0.911', '550', 'userunknown',     1]],
    '1031'  => [['4.0.947', '',    'expired',         0]],
    '1032'  => [['5.0.911', '550', 'userunknown',     1]],
    '1033'  => [['5.0.911', '550', 'userunknown',     1]],
    '1034'  => [['5.0.911', '550', 'userunknown',     1]],
    '1035'  => [['5.1.8',   '550', 'rejected',        0]],
    '1036'  => [['5.0.911', '550', 'userunknown',     1]],
    '1037'  => [['4.0.947', '',    'expired',         0]],
    '1038'  => [['5.7.0',   '550', 'blocked',         0]],
    '1039'  => [['4.0.922', '',    'mailboxfull',     0]],
    '1040'  => [['4.0.947', '',    'expired',         0]],
    '1041'  => [['4.0.947', '451', 'spamdetected',    0]],
    '1042'  => [['5.0.944', '',    'networkerror',    0]],
    '1043'  => [['5.0.911', '550', 'userunknown',     1]],
    '1044'  => [['5.0.944', '',    'networkerror',    0]],
    '1045'  => [['5.0.912', '',    'hostunknown',     1]],
    '1046'  => [['5.0.911', '550', 'userunknown',     1]],
    '1047'  => [['5.0.911', '550', 'userunknown',     1]],
    '1049'  => [['5.0.921', '554', 'suspend',         0]],
    '1050'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1051'  => [['5.0.911', '550', 'userunknown',     1]],
    '1053'  => [['5.0.911', '550', 'userunknown',     1]],
    '1054'  => [['5.0.921', '554', 'suspend',         0]],
    '1055'  => [['5.0.911', '550', 'userunknown',     1]],
    '1056'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1057'  => [['5.0.921', '554', 'suspend',         0]],
    '1058'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1059'  => [['5.0.901', '550', 'onhold',          0]],
    '1060'  => [['4.0.947', '',    'expired',         0]],
    '1061'  => [['5.0.911', '550', 'userunknown',     1]],
    '1062'  => [['5.0.911', '550', 'userunknown',     1]],
    '1063'  => [['5.0.911', '550', 'userunknown',     1]],
    '1064'  => [['5.0.911', '550', 'userunknown',     1]],
    '1065'  => [['5.0.911', '550', 'userunknown',     1]],
    '1066'  => [['5.0.911', '550', 'userunknown',     1]],
    '1067'  => [['5.0.911', '550', 'userunknown',     1]],
    '1068'  => [['5.0.911', '550', 'userunknown',     1]],
    '1069'  => [['5.0.911', '550', 'userunknown',     1]],
    '1070'  => [['5.0.911', '550', 'userunknown',     1]],
    '1071'  => [['5.0.911', '550', 'userunknown',     1]],
    '1072'  => [['5.2.1',   '554', 'userunknown',     1]],
    '1073'  => [['5.0.921', '554', 'suspend',         0]],
    '1074'  => [['5.0.911', '550', 'userunknown',     1]],
    '1075'  => [['5.0.911', '550', 'userunknown',     1]],
    '1076'  => [['5.0.911', '550', 'userunknown',     1]],
    '1077'  => [['5.0.921', '554', 'suspend',         0]],
    '1078'  => [['5.0.900', '',    'undefined',       0]],
    '1079'  => [['5.0.0',   '',    'hostunknown',     1],
                ['5.0.0',   '',    'hostunknown',     1]],
    '1080'  => [['5.0.0',   '',    'hostunknown',     1]],
    '1081'  => [['5.0.0',   '',    'hostunknown',     1]],
    '1082'  => [['5.0.901', '',    'onhold',          0]],
    '1083'  => [['5.0.0',   '',    'mailererror',     0]],
    '1084'  => [['5.0.0',   '550', 'systemerror',     0],
                ['5.0.0',   '550', 'systemerror',     0]],
    '1085'  => [['5.0.0',   '550', 'blocked',         0],
                ['5.0.971', '550', 'blocked',         0]],
    '1086'  => [['5.0.0',   '',    'onhold',          0],
                ['5.0.0',   '',    'onhold',          0],
                ['5.0.0',   '',    'onhold',          0],
                ['5.0.0',   '',    'onhold',          0]],
    '1087'  => [['5.0.0',   '550', 'onhold',          0]],
    '1088'  => [['5.0.901', '550', 'onhold',          0],
                ['5.0.0',   '550', 'onhold',          0]],
    '1089'  => [['5.0.0',   '',    'mailererror',     0],
                ['5.0.0',   '',    'mailererror',     0]],
    '1090'  => [['5.0.0',   '',    'onhold',          0],
                ['5.0.0',   '',    'onhold',          0]],
    '1091'  => [['5.0.0',   '',    'onhold',          0]],
    '1092'  => [['5.0.0',   '',    'undefined',       0]],
    '1094'  => [['5.0.0',   '',    'onhold',          0]],
    '1095'  => [['5.0.0',   '',    'undefined',       0]],
    '1098'  => [['4.0.947', '',    'expired',         0],
                ['4.0.947', '',    'expired',         0]],
    '1099'  => [['4.0.947', '',    'expired',         0]],
    '1100'  => [['5.0.0',   '',    'mailererror',     0],
                ['5.0.0',   '',    'mailererror',     0],
                ['5.0.0',   '',    'mailererror',     0],
                ['5.0.0',   '',    'mailererror',     0],
                ['5.0.0',   '',    'mailererror',     0]],
    '1101'  => [['5.0.0',   '',    'mailererror',     0]],
    '1103'  => [['5.0.900', '',    'undefined',       0],
                ['5.0.900', '',    'undefined',       0],
                ['5.0.0',   '',    'undefined',       0]],
    '1104'  => [['5.0.0',   '',    'mailererror',     0],
                ['5.0.0',   '',    'mailererror',     0]],
    '1105'  => [['5.0.0',   '',    'mailererror',     0]],
    '1106'  => [['5.0.0',   '',    'onhold',          0]],
    '1107'  => [['5.0.980', '',    'spamdetected',    0]],
    '1109'  => [['5.7.1',   '554', 'userunknown',     1]],
    '1110'  => [['5.0.912', '',    'hostunknown',     1],
                ['5.0.912', '',    'hostunknown',     1]],
    '1111'  => [['5.0.973', '',    'requireptr',      0]],
    '1112'  => [['5.0.973', '554', 'requireptr',      0]],
    '1113'  => [['5.7.1',   '554', 'requireptr',      0]],
    '1114'  => [['5.0.971', '550', 'blocked',         0]],
    '1115'  => [['5.0.901', '550', 'rejected',        0]],
    '1116'  => [['5.0.912', '553', 'hostunknown',     1]],
    '1117'  => [['4.0.901', '450', 'requireptr',      0]],
    '1118'  => [['5.0.973', '550', 'requireptr',      0]],
    '1119'  => [['5.0.901', '551', 'requireptr',      0]],
    '1120'  => [['4.0.901', '450', 'requireptr',      0]],
    '1121'  => [['5.7.1',   '554', 'requireptr',      0]],
    '1122'  => [['5.7.1',   '550', 'requireptr',      0]],
    '1123'  => [['5.0.0',   '',    'mailererror',     0]],
    '1124'  => [['5.2.0',   '550', 'rejected',        0]],
    '1125'  => [['5.7.1',   '554', 'blocked',         0]],
    '1126'  => [['5.0.971', '550', 'blocked',         0]],
    '1127'  => [['5.7.1',   '550', 'requireptr',      0]],
    '1128'  => [['5.0.0',   '550', 'blocked',         0]],
    '1129'  => [['5.1.7',   '550', 'rejected',        0]],
    '1130'  => [['5.1.0',   '553', 'rejected',        0]],
    '1131'  => [['5.0.902', '',    'syntaxerror',     0]],
    '1132'  => [['5.0.939', '',    'mailererror',     0]],
    '1133'  => [['5.0.901', '550', 'blocked',         0]],
    '1134'  => [['5.7.0',   '554', 'spamdetected',    0]],
    '1135'  => [['5.0.971', '554', 'blocked',         0]],
    '1136'  => [['5.0.918', '',    'rejected',        0]],
    '1137'  => [['5.0.911', '550', 'userunknown',     1]],
    '1138'  => [['5.0.901', '550', 'blocked',         0]],
    '1139'  => [['5.0.918', '550', 'rejected',        0]],
    '1140'  => [['5.0.945', '',    'toomanyconn',     0]],
    '1141'  => [['5.0.910', '',    'filtered',        0]],
    '1142'  => [['5.0.981', '',    'virusdetected',   0]],
    '1143'  => [['5.0.911', '550', 'userunknown',     1]],
    '1145'  => [['5.0.934', '500', 'mesgtoobig',      0]],
    '1146'  => [['5.0.911', '550', 'userunknown',     1]],
    '1147'  => [['5.0.901', '551', 'blocked',         0]],
    '1148'  => [['5.0.980', '550', 'spamdetected',    0]],
    '1149'  => [['5.0.901', '550', 'rejected',        0]],
    '1150'  => [['5.7.1',   '553', 'blocked',         0]],
    '1151'  => [['5.0.0',   '550', 'suspend',         0]],
    '1152'  => [['5.0.0',   '550', 'blocked',         0]],
    '1153'  => [['5.0.0',   '550', 'blocked',         0]],
    '1154'  => [['5.7.1',   '550', 'blocked',         0]],
    '1155'  => [['5.0.0',   '550', 'blocked',         0]],
    '1156'  => [['5.0.0',   '550', 'blocked',         0]],
    '1157'  => [['5.0.0',   '',    'spamdetected',    0]],
    '1158'  => [['5.0.0',   '',    'filtered',        0]],
    '1159'  => [['5.0.0',   '',    'spamdetected',    0]],
    '1161'  => [['5.3.4',   '552', 'mesgtoobig',      0],
                ['5.3.4',   '552', 'mesgtoobig',      0],
                ['5.3.4',   '552', 'mesgtoobig',      0],
                ['5.3.4',   '552', 'mesgtoobig',      0]],
    '1162'  => [['5.7.1',   '550', 'requireptr',      0]],
    '1163'  => [['5.1.1',   '550', 'mailboxfull',     0]],
    '1164'  => [['5.7.1',   '553', 'authfailure',     0]],
    '1165'  => [['5.7.1',   '550', 'spamdetected',    0]],
    '1168'  => [['4.0.947', '',    'expired',         0]],
    '1169'  => [['5.4.3',   '',    'systemerror',     0]],
    '1170'  => [['5.0.0',   '',    'systemerror',     0],
                ['5.0.0',   '',    'systemerror',     0]],
    '1171'  => [['5.0.0',   '',    'mailboxfull',     0]],
    '1172'  => [['5.0.0',   '',    'hostunknown',     1],
                ['5.0.0',   '',    'hostunknown',     1]],
    '1173'  => [['5.0.0',   '',    'networkerror',    0]],
    '1175'  => [['5.0.0',   '',    'expired',         0],
                ['5.0.0',   '',    'expired',         0],
                ['5.0.0',   '',    'expired',         0]],
    '1176'  => [['5.0.0',   '550', 'userunknown',     1]],
    '1177'  => [['5.0.0',   '',    'filtered',        0],
                ['5.0.0',   '',    'filtered',        0]],
    '1178'  => [['4.0.947', '',    'expired',         0]],
    '1179'  => [['5.0.0',   '',    'mailererror',     0],
                ['5.0.0',   '',    'mailererror',     0]],
    '1181'  => [['5.0.0',   '',    'mailererror',     0],
                ['5.0.939', '',    'mailererror',     0],
                ['5.0.0',   '',    'mailererror',     0]],
    '1182'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1183'  => [['5.0.0',   '',    'mailboxfull',     0]],
    '1184'  => [['5.1.1',   '550', 'userunknown',     1]],
    '1185'  => [['5.0.0',   '554', 'suspend',         0]],
    '1186'  => [['5.0.0',   '550', 'userunknown',     1]],
    '1187'  => [['5.0.0',   '',    'hostunknown',     1]],
    '1188'  => [['5.2.0',   '550', 'spamdetected',    0]],
    '1189'  => [['5.0.0',   '',    'expired',         0]],
    '1190'  => [['5.0.0',   '',    'hostunknown',     1]],
    '1191'  => [['5.0.0',   '550', 'suspend',         0]],
};

plan 'skip_all', sprintf("%s not found", $samplepath) unless -d $samplepath;
$enginetest->($enginename, $isexpected, 1, 0);
done_testing;

