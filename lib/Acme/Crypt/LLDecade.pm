package Acme::Crypt::LLDecade;

use strict;
use warnings;
use 5.10.0;
our $VERSION = '0.01';
use Regexp::Common 'net';
use Regexp::IPv6 '$IPv6_re';
use Filter::Util::Call;

sub import {
    my $class = shift;
    Filter::Util::Call::filter_add(sub {
        my $status;
        my $code = '';
        my $count = 0;
        my $org = '';
        my $skip = 0;
        while ($status = Filter::Util::Call::filter_read()) {
            return $status if $status < 0;
            $count++;
            $org .= $_;
            chomp;

            $skip = 1 if $_ =~ /\s/;
            next if $skip;

            my $line = $_;
            if ($line =~ /^$RE{net}{IPv4}{dec}$/) {
                for my $o (split /\./, $line) {
                    if (length($o) > 1 && $o =~ /^0/) {
                        $line = 'XXXX';
                        last;
                    }
                }
            }
            elsif ($line =~ /^$IPv6_re$/) {
                for my $o (split ':', $line) {
                    if (length($o) > 1 && $o =~ /^0/) {
                        $line = 'XXX';
                        last;
                    }
                }
            }

            given ($line) {
                $code .= '00' when /^
                    $RE{net}{MAC}{dec}{-sep => '-'}
                    |$RE{net}{MAC}{hex}{-sep => '-'}
                    |$RE{net}{MAC}
                $/x;
                $code .= '01' when /^$RE{net}{IPv4}$/;
                $code .= '10' when /^$IPv6_re$/;
                $code .= '11';
            }
            $_ = '';
        }
        
        $_ = $skip ? $org : pack 'B*' => $code;
        return $count;
    });
    
    return 1;
}

1;
__END__

=encoding utf-8

=for stopwords

=head1 NAME

Acme::Crypt::LLDecade - Crypt LLDecade Online quiz library for Perl

=head1 SYNOPSIS

  $ cat foo.pl
  use Acme::Crypt::LLDecade;
  69.166.168.68
  8uY$&.?peNtJut01
  9B:Eb:ce:B8:0c:A2
  C8-4d-Bf-bf-EB-34
  108.70.103.5
  1N"DC3;Cl,Cu[
  6b-dd-17-95-e4-C6
  ECC3:4B31:7E8A:58A1:5D6F:760E:1D37:7D0A
  231.167.28.210
  7528:39DD:3D47:E536:F1B4:F28B:D695:90BA
  B592:1053:8F2D:90EA:FCEA:1DED:EAC9:BE99
  73.94.217.167
  197.57.129.65
  C9C0:AA9C:F7DA:B975:CCA7:E094:868D:E990
  d>m(d^l_7<e?_tjQ
  8FF0:AACD:25ED:9650:3C6C:ADDA:1CD3:4B8F
  157.249.167.178
  0rxR~(N*yp)xzL&!s+
  154.64.232.196
  cE:93:0C:cd:Cb:Fd
  9b:CC:8D:ed:de:66
  3E8F:2F25:C570:DD44:F46E:BA0C:B4A9:8F47
  7e-75-F3-A5-8B-8A
  03:13:08:4b:45:C0
  6C-c7-cf-77-e0-72
  EFA3:362A:6A22:5877:3657:F4D0:27E0:7AE5
  B2:9f:17:61:5b:C5
  EE91:135A:BFF1:1475:E35C:570C:CDDC:C4E8
  142.129.168.169
  bC:a9:Ae:b3:6A:Bf
  2B2B:BA8E:C878:A7C7:8A28:4923:1AE5:446A
  e9-0E-2E-FB-7b-33
  86.84.13.1
  FE9C:4060:C670:E710:B4D6:9885:7F3C:18AC
  83.168.102.182
  115.102.178.96
  124.10.236.78
  9CED:267D:7747:98D1:C8FD:6C45:9DB1:9312
  0,Er;uZIup"Xce0
  0c:CC:3b:d8:bD:DA
  183.177.112.39
  2F31:81B5:F8B5:569D:7AAA:DD26:C449:8BC7
  5x_8_!HW
  4D-c2-EC-E8-8C-d4
  47.236.240.165
  143B:F078:7C92:8DC2:5FBB:E817:F4AF:47C9
  D2]LNSObR
  d~p@\RHAL5XCl*k+
  Bf-fD-Dd-E0-77-e5
  F31E:597D:CA41:9413:B46E:4575:AE21:467F
  3doO]
  BB-8e-25-31-d3-AE
  Ce-ad-80-F3-a9-Ac
  7518:127D:BD0D:E165:173E:9883:4B25:E231
  B0:fe:33:A1:AE:41
  29:a5:62:5b:5a:0E
  177.80.138.220
  196.51.251.15
  121.111.34.210
  D8Ei2
  117.139.116.178
  6E69:B6D5:761F:7671:AE2A:4283:3DE6:833A
  F=K='Q
  0J9SL
  148.80.0.25
  e-)74/ZLxIsl$h
  df-aF-Ec-fc-d7-4d
  F228:E91C:BC14:B5F4:6C54:AAD4:94D7:D1A9
  206.236.198.81
  5351:7DF0:F4EE:D2B9:D673:40B0:3939:265D
  an
  59:fd:a1:e5:f0:cC
  228.113.194.43
  5B09:C4D3:5E2D:3640:88EC:3CF8:D40E:5D43
  62.92.6.167
  6C-3a-7C-9e-Cc-B7
  141.187.95.158
  59.24.185.166
  EB=,Ei,vg(Ez
  5B:dd:78:aF:BD:59
  182.62.192.135
  3D5D:FD3E:1D81:6F52:735D:DFCA:7D16:27F0
  BVH!_
  303E:D273:E4AE:978D:857F:EBBB:C687:8F06
  D2:65:FA:21:fE:79
  D126:4886:1859:38B8:AF60:AEA8:22C2:C195
  A3:E7:cc:bC:0A:E0
  ECDD:148E:CD38:6E92:5B2C:ADE8:C99E:37A5
  fe-3C-71-c2-BC-b6
  c{,">
  3E8A:454A:3872:B5DD:821C:FC57:3165:1BBD
  8!'qM%
  a9:c5:a5:9b:1F:aB
  Ca:0a:Ec:aD:be:c4
  9408:73CE:CB67:FD08:C752:5793:D5CD:C08E
  28D4:8ABC:ED42:D8CF:614E:9A34:7760:254F

  $ ./foo.pl
  Hello, World

=head1 DESCRIPTION

Acme::Crypt::LLDecade is runs encrypted perl code from LLDecade encryption.

SEE ALSO L<< http://ll.jus.or.jp/2012/doukaku-online-main.html >>

=head1 SCRIPTS

=head2 lldecade-encrypt

  Usage: lldecade-encrypt [options] <file>

  Options:
    --perl  Create runnable perl script

=head2 lldecade-decrypt

  Usage: lldecade-decrypt <file>

=head1 AUTHOR

xaicron E<lt>xaicron@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2012 - xaicron

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

=cut
