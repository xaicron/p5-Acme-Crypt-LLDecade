#!/usr/bin/env perl

use strict;
use warnings;
use 5.10.0;

my $decripter = 'assets/lldecade-encrypt';
for my $file (qw/lldecade-decrypt lldecade-encrypt/) {
    say "encrypting assets/$file -> bin/$file";
    my $ret = `perl -Ilib $decripter assets/$file`;
    open my $fh, '>', "bin/$file" or die $!;
    say $fh '#!perl';
    say $fh 'use Acme::Crypt::LLDecade;';
    print $fh $ret;
    chmod 0755, $fh unless $^O eq 'MSWin32';
}

say 'done.';
