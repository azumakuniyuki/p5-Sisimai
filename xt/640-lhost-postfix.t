use strict;
use warnings;
use Test::More;
use lib qw(./lib ./blib/lib);
require './t/600-lhost-code';

my $enginename = 'Postfix';
my $samplepath = sprintf("./set-of-emails/private/lhost-%s", lc $enginename);
my $enginetest = Sisimai::Lhost::Code->maketest;
my $isexpected = [
    { 'n' => '01001', 'r' => qr/filtered/       },
    { 'n' => '01002', 'r' => qr/userunknown/    },
    { 'n' => '01003', 'r' => qr/userunknown/    },
    { 'n' => '01004', 'r' => qr/userunknown/    },
    { 'n' => '01005', 'r' => qr/filtered/       },
    { 'n' => '01006', 'r' => qr/userunknown/    },
    { 'n' => '01007', 'r' => qr/filtered/       },
    { 'n' => '01008', 'r' => qr/filtered/       },
    { 'n' => '01009', 'r' => qr/userunknown/    },
    { 'n' => '01010', 'r' => qr/hostunknown/    },
    { 'n' => '01011', 'r' => qr/systemerror/    },
    { 'n' => '01012', 'r' => qr/userunknown/    },
    { 'n' => '01013', 'r' => qr/userunknown/    },
    { 'n' => '01014', 'r' => qr/userunknown/    },
    { 'n' => '01015', 'r' => qr/userunknown/    },
    { 'n' => '01016', 'r' => qr/toomanyconn/    },
    { 'n' => '01017', 'r' => qr/expired/        },
    { 'n' => '01018', 'r' => qr/systemerror/    },
    { 'n' => '01019', 'r' => qr/userunknown/    },
    { 'n' => '01020', 'r' => qr/userunknown/    },
    { 'n' => '01021', 'r' => qr/expired/        },
    { 'n' => '01022', 'r' => qr/userunknown/    },
    { 'n' => '01023', 'r' => qr/blocked/        },
    { 'n' => '01024', 'r' => qr/userunknown/    },
    { 'n' => '01025', 'r' => qr/userunknown/    },
    { 'n' => '01026', 'r' => qr/expired/        },
    { 'n' => '01027', 'r' => qr/systemerror/    },
    { 'n' => '01028', 'r' => qr/suspend/        },
    { 'n' => '01029', 'r' => qr/userunknown/    },
    { 'n' => '01030', 'r' => qr/userunknown/    },
    { 'n' => '01031', 'r' => qr/userunknown/    },
    { 'n' => '01032', 'r' => qr/userunknown/    },
    { 'n' => '01033', 'r' => qr/userunknown/    },
    { 'n' => '01034', 'r' => qr/filtered/       },
    { 'n' => '01035', 'r' => qr/mailboxfull/    },
    { 'n' => '01036', 'r' => qr/hostunknown/    },
    { 'n' => '01037', 'r' => qr/filtered/       },
    { 'n' => '01038', 'r' => qr/blocked/        },
    { 'n' => '01039', 'r' => qr/userunknown/    },
    { 'n' => '01040', 'r' => qr/userunknown/    },
    { 'n' => '01041', 'r' => qr/userunknown/    },
    { 'n' => '01042', 'r' => qr/networkerror/   },
    { 'n' => '01043', 'r' => qr/hasmoved/       },
    { 'n' => '01044', 'r' => qr/mesgtoobig/     },
    { 'n' => '01045', 'r' => qr/mesgtoobig/     },
    { 'n' => '01046', 'r' => qr/mesgtoobig/     },
    { 'n' => '01047', 'r' => qr/mesgtoobig/     },
    { 'n' => '01048', 'r' => qr/userunknown/    },
    { 'n' => '01049', 'r' => qr/hostunknown/    },
    { 'n' => '01050', 'r' => qr/userunknown/    },
    { 'n' => '01051', 'r' => qr/norelaying/     },
    { 'n' => '01052', 'r' => qr/spamdetected/   },
    { 'n' => '01053', 'r' => qr/systemerror/    },
    { 'n' => '01054', 'r' => qr/userunknown/    },
    { 'n' => '01055', 'r' => qr/filtered/       },
    { 'n' => '01056', 'r' => qr/mailererror/    },
    { 'n' => '01057', 'r' => qr/userunknown/    },
    { 'n' => '01058', 'r' => qr/filtered/       },
    { 'n' => '01059', 'r' => qr/userunknown/    },
    { 'n' => '01060', 'r' => qr/userunknown/    },
    { 'n' => '01061', 'r' => qr/hostunknown/    },
    { 'n' => '01062', 'r' => qr/filtered/       },
    { 'n' => '01063', 'r' => qr/mailererror/    },
    { 'n' => '01064', 'r' => qr/hostunknown/    },
    { 'n' => '01065', 'r' => qr/networkerror/   },
    { 'n' => '01066', 'r' => qr/norelaying/     },
    { 'n' => '01067', 'r' => qr/userunknown/    },
    { 'n' => '01068', 'r' => qr/norelaying/     },
    { 'n' => '01069', 'r' => qr/userunknown/    },
    { 'n' => '01070', 'r' => qr/networkerror/   },
    { 'n' => '01071', 'r' => qr/mailboxfull/    },
    { 'n' => '01072', 'r' => qr/onhold/         },
    { 'n' => '01073', 'r' => qr/mailboxfull/    },
    { 'n' => '01074', 'r' => qr/mailboxfull/    },
    { 'n' => '01075', 'r' => qr/mailboxfull/    },
    { 'n' => '01076', 'r' => qr/filtered/       },
    { 'n' => '01077', 'r' => qr/norelaying/     },
    { 'n' => '01078', 'r' => qr/norelaying/     },
    { 'n' => '01079', 'r' => qr/spamdetected/   },
    { 'n' => '01080', 'r' => qr/spamdetected/   },
    { 'n' => '01081', 'r' => qr/spamdetected/   },
    { 'n' => '01082', 'r' => qr/spamdetected/   },
    { 'n' => '01083', 'r' => qr/spamdetected/   },
    { 'n' => '01084', 'r' => qr/spamdetected/   },
    { 'n' => '01085', 'r' => qr/spamdetected/   },
    { 'n' => '01086', 'r' => qr/spamdetected/   },
    { 'n' => '01087', 'r' => qr/spamdetected/   },
    { 'n' => '01088', 'r' => qr/spamdetected/   },
    { 'n' => '01089', 'r' => qr/spamdetected/   },
    { 'n' => '01090', 'r' => qr/spamdetected/   },
    { 'n' => '01091', 'r' => qr/spamdetected/   },
    { 'n' => '01092', 'r' => qr/spamdetected/   },
    { 'n' => '01093', 'r' => qr/spamdetected/   },
    { 'n' => '01094', 'r' => qr/spamdetected/   },
    { 'n' => '01095', 'r' => qr/spamdetected/   },
    { 'n' => '01096', 'r' => qr/spamdetected/   },
    { 'n' => '01097', 'r' => qr/spamdetected/   },
    { 'n' => '01098', 'r' => qr/spamdetected/   },
    { 'n' => '01099', 'r' => qr/spamdetected/   },
    { 'n' => '01100', 'r' => qr/spamdetected/   },
    { 'n' => '01101', 'r' => qr/policyviolation/ },
    { 'n' => '01102', 'r' => qr/spamdetected/   },
    { 'n' => '01103', 'r' => qr/spamdetected/   },
    { 'n' => '01104', 'r' => qr/spamdetected/   },
    { 'n' => '01105', 'r' => qr/spamdetected/   },
    { 'n' => '01106', 'r' => qr/spamdetected/   },
    { 'n' => '01107', 'r' => qr/spamdetected/   },
    { 'n' => '01108', 'r' => qr/spamdetected/   },
    { 'n' => '01109', 'r' => qr/spamdetected/   },
    { 'n' => '01110', 'r' => qr/spamdetected/   },
    { 'n' => '01111', 'r' => qr/spamdetected/   },
    { 'n' => '01112', 'r' => qr/spamdetected/   },
    { 'n' => '01113', 'r' => qr/spamdetected/   },
    { 'n' => '01114', 'r' => qr/spamdetected/   },
    { 'n' => '01115', 'r' => qr/blocked/        },
    { 'n' => '01116', 'r' => qr/spamdetected/   },
    { 'n' => '01117', 'r' => qr/spamdetected/   },
    { 'n' => '01118', 'r' => qr/spamdetected/   },
    { 'n' => '01119', 'r' => qr/spamdetected/   },
    { 'n' => '01120', 'r' => qr/spamdetected/   },
    { 'n' => '01121', 'r' => qr/spamdetected/   },
    { 'n' => '01122', 'r' => qr/hostunknown/    },
    { 'n' => '01123', 'r' => qr/userunknown/    },
    { 'n' => '01124', 'r' => qr/userunknown/    },
    { 'n' => '01125', 'r' => qr/exceedlimit/    },
    { 'n' => '01126', 'r' => qr/systemerror/    },
    { 'n' => '01127', 'r' => qr/userunknown/    },
    { 'n' => '01128', 'r' => qr/userunknown/    },
    { 'n' => '01129', 'r' => qr/filtered/       },
    { 'n' => '01130', 'r' => qr/mailboxfull/    },
    { 'n' => '01131', 'r' => qr/exceedlimit/    },
    { 'n' => '01132', 'r' => qr/userunknown/    },
    { 'n' => '01133', 'r' => qr/userunknown/    },
    { 'n' => '01134', 'r' => qr/userunknown/    },
    { 'n' => '01135', 'r' => qr/suspend/        },
    { 'n' => '01136', 'r' => qr/userunknown/    },
    { 'n' => '01137', 'r' => qr/userunknown/    },
    { 'n' => '01138', 'r' => qr/userunknown/    },
    { 'n' => '01139', 'r' => qr/userunknown/    },
    { 'n' => '01140', 'r' => qr/userunknown/    },
    { 'n' => '01141', 'r' => qr/filtered/       },
    { 'n' => '01142', 'r' => qr/blocked/        },
    { 'n' => '01143', 'r' => qr/userunknown/    },
    { 'n' => '01144', 'r' => qr/suspend/        },
    { 'n' => '01145', 'r' => qr/filtered/       },
    { 'n' => '01146', 'r' => qr/userunknown/    },
    { 'n' => '01147', 'r' => qr/userunknown/    },
    { 'n' => '01148', 'r' => qr/userunknown/    },
    { 'n' => '01149', 'r' => qr/mailboxfull/    },
    { 'n' => '01150', 'r' => qr/filtered/       },
    { 'n' => '01151', 'r' => qr/spamdetected/   },
    { 'n' => '01152', 'r' => qr/blocked/        },
    { 'n' => '01153', 'r' => qr/blocked/        },
    { 'n' => '01154', 'r' => qr/blocked/        },
    { 'n' => '01155', 'r' => qr/userunknown/    },
    { 'n' => '01156', 'r' => qr/userunknown/    },
    { 'n' => '01157', 'r' => qr/blocked/        },
    { 'n' => '01158', 'r' => qr/spamdetected/   },
    { 'n' => '01159', 'r' => qr/userunknown/    },
    { 'n' => '01160', 'r' => qr/systemerror/    },
    { 'n' => '01161', 'r' => qr/mailboxfull/    },
    { 'n' => '01162', 'r' => qr/policyviolation/},
    { 'n' => '01163', 'r' => qr/policyviolation/},
    { 'n' => '01164', 'r' => qr/blocked/        },
    { 'n' => '01165', 'r' => qr/userunknown/    },
    { 'n' => '01166', 'r' => qr/userunknown/    },
    { 'n' => '01167', 'r' => qr/blocked/        },
    { 'n' => '01168', 'r' => qr/rejected/       },
    { 'n' => '01169', 'r' => qr/userunknown/    },
    { 'n' => '01170', 'r' => qr/blocked/        },
    { 'n' => '01171', 'r' => qr/mailboxfull/    },
    { 'n' => '01172', 'r' => qr/mailererror/    },
    { 'n' => '01173', 'r' => qr/networkerror/   },
    { 'n' => '01174', 'r' => qr/notaccept/      },
    { 'n' => '01175', 'r' => qr/policyviolation/},
    { 'n' => '01176', 'r' => qr/userunknown/    },
    { 'n' => '01177', 'r' => qr/userunknown/    },
    { 'n' => '01178', 'r' => qr/blocked/        },
    { 'n' => '01179', 'r' => qr/norelaying/     },
    { 'n' => '01180', 'r' => qr/rejected/       },
    { 'n' => '01181', 'r' => qr/userunknown/    },
    { 'n' => '01182', 'r' => qr/spamdetected/   },
    { 'n' => '01183', 'r' => qr/userunknown/    },
    { 'n' => '01184', 'r' => qr/norelaying/     },
    { 'n' => '01185', 'r' => qr/systemerror/    },
    { 'n' => '01186', 'r' => qr/userunknown/    },
    { 'n' => '01187', 'r' => qr/userunknown/    },
    { 'n' => '01188', 'r' => qr/expired/        },
    { 'n' => '01189', 'r' => qr/hostunknown/    },
    { 'n' => '01190', 'r' => qr/userunknown/    },
    { 'n' => '01191', 'r' => qr/userunknown/    },
    { 'n' => '01192', 'r' => qr/toomanyconn/    },
    { 'n' => '01193', 'r' => qr/filtered/       },
    { 'n' => '01194', 'r' => qr/userunknown/    },
    { 'n' => '01195', 'r' => qr/expired/        },
    { 'n' => '01196', 'r' => qr/userunknown/    },
    { 'n' => '01197', 'r' => qr/userunknown/    },
    { 'n' => '01198', 'r' => qr/systemerror/    },
    { 'n' => '01199', 'r' => qr/toomanyconn/    },
    { 'n' => '01200', 'r' => qr/blocked/        },
    { 'n' => '01201', 'r' => qr/blocked/        },
    { 'n' => '01202', 'r' => qr/policyviolation/ },
    { 'n' => '01203', 'r' => qr/suspend/        },
    { 'n' => '01204', 'r' => qr/syntaxerror/    },
    { 'n' => '01205', 'r' => qr/rejected/       },
    { 'n' => '01206', 'r' => qr/toomanyconn/    },
    { 'n' => '01207', 'r' => qr/toomanyconn/    },
    { 'n' => '01208', 'r' => qr/toomanyconn/    },
    { 'n' => '01209', 'r' => qr/networkerror/   },
    { 'n' => '01210', 'r' => qr/blocked/        },
    { 'n' => '01211', 'r' => qr/userunknown/    },
    { 'n' => '01212', 'r' => qr/userunknown/    },
    { 'n' => '01213', 'r' => qr/userunknown/    },
    { 'n' => '01214', 'r' => qr/exceedlimit/    },
    { 'n' => '01215', 'r' => qr/exceedlimit/    },
    { 'n' => '01216', 'r' => qr/blocked/        },
    { 'n' => '01217', 'r' => qr/blocked/        },
    { 'n' => '01218', 'r' => qr/blocked/        },
    { 'n' => '01219', 'r' => qr/suspend/        },
    { 'n' => '01220', 'r' => qr/virusdetected/  },
    { 'n' => '01221', 'r' => qr/userunknown/    },
    { 'n' => '01222', 'r' => qr/mailboxfull/    },
];

plan 'skip_all', sprintf("%s not found", $samplepath) unless -d $samplepath;
$enginetest->($enginename, $isexpected, 1, 0);
done_testing;

