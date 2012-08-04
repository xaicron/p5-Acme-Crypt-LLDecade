use inc::Module::Install;
use Module::Install::AuthorTests;

name 'Acme-Crypt-LLDecade';
all_from 'lib/Acme/Crypt/LLDecade.pm';

requires 'String::Random';
requires 'Regexp::Common';
requires 'Regexp::IPv6';
requires 'Filter::Util::Call';

test_requires 'Test::More', 0.98;

tests join q{ }, map { sprintf 't%s.t', '/*' x $_ } 1..3;
author_tests 'xt';

repository 'http://github.com/xaicron/p5-Acme-Crypt-LLDecade/';
bugtracker 'http://github.com/xaicron/p5-Acme-Crypt-LLDecade/issues';

install_script 'bin/lldecade-encrypt';
install_script 'bin/lldecade-decrypt';

WriteAll;
