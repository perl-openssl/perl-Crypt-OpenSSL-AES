use strict;
use warnings;
use Test::More tests => 7;
use Crypt::Mode::OFB;
use Crypt::PRNG qw(rand);
use Crypt::Digest::SHA512_256 qw( sha512_256_hex );
use Crypt::OpenSSL::Guess qw(openssl_version openssl_inc_paths openssl_lib_paths find_openssl_exec find_openssl_prefix);
my ($major, $minor, $patch) = openssl_version();
my $prefix          = find_openssl_prefix();
my $openssl         = find_openssl_exec($prefix);
my $version_string  = `$openssl version`;
$version_string =~ m/(^[A-z]+)/;
print "Installed $1: $major.$minor", defined $patch ? $patch : "", "\n";

BEGIN { use_ok('Crypt::OpenSSL::AES') };

my @keysize = ("128", "192", "256");
foreach my $ks (@keysize) {
    SKIP: {
        skip 'OpenSSL 3.0+ is not available', 2 if( $major lt "3.0" );
        skip "LibreSSL is installed", 2 if ($version_string =~ /LibreSSL/);
        my $key = pack("H*", substr(sha512_256_hex(rand(1000)), 0, ($ks/4)));
        my $iv  = pack("H*", substr(sha512_256_hex(rand(1000)), 0, 32));

        my $coa = Crypt::OpenSSL::AES->new($key,
                                        {
                                        cipher  => "AES-$ks-OFB",
                                        iv      => $iv,
                                        });

        my $ecb = Crypt::Mode::OFB->new('AES');

        my $encrypted = $coa->encrypt("Hello World. 123");
        my $plaintext = $ecb->decrypt($encrypted, $key, $iv);

        ok($plaintext eq "Hello World. 123", "Crypt::OpenSSL::AES ($ks) - Decrypted with Crypt::Mode::OFB");

        $encrypted = $ecb->encrypt("Hello World. 123", $key, $iv);
        $plaintext = $coa->decrypt($encrypted);

        ok($plaintext eq "Hello World. 123", "Crypt::Mode::OFB ($ks) - Decrypted with Crypt::OpenSSL::AES");
    }
}
done_testing;
