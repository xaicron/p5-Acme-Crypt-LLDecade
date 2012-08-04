use inc::Module::Install;
use Module::Install::AuthorTests;

name 'Acme-Crypt-LLDecade';
all_from 'lib/Acme/Crypt/LLDecade.pm';

#requires '';

test_requires 'Test::More', 0.98;

tests join q{ }, map { sprintf 't%s.t', '/*' x $_ } 1..3;
author_tests 'xt';

repository 'http://github.com/xaicron/p5-Acme-Crypt-LLDecade/';
bugtracker 'http://github.com/xaicron/p5-Acme-Crypt-LLDecade/issues';

WriteAll;
