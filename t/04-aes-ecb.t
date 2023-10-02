use strict;
use warnings;
use Test::More tests => 15;
use Crypt::Mode::ECB;
use Crypt::PRNG qw(rand);
use Crypt::Digest::SHA512_256 qw( sha512_256_hex );
use Crypt::OpenSSL::Guess qw(openssl_version openssl_inc_paths openssl_lib_paths);
my ($major, $minor, $patch) = openssl_version();
print "Installed OpenSSL: $major.$minor", defined $patch ? $patch : "", "\n";

BEGIN { use_ok('Crypt::OpenSSL::AES') };


my $key = pack("C*",0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33);

my $plaintext = pack("C*",0x41,0x42,0x43,0x44,0x41,0x42,0x43,0x44,0x41,0x42,0x43,0x44,0x41,0x42,0x43,0x44);

my $expected_enc = pack("C*", 0x9b, 0xc3, 0x7f, 0x1b, 0x92, 0x93, 0xcc, 0xf9, 0x6b, 0x64, 0x00, 0xae, 0xa3, 0xc8, 0x85, 0xbb);

my $c = Crypt::OpenSSL::AES->new($key,
                                    {
                                    cipher  => 'AES-256-ECB',
                                    });

my $encrypted = $c->encrypt($plaintext);

ok($encrypted eq $expected_enc, "Encrypted Successfully AES-256-ECB");

ok($c->decrypt($encrypted) eq $plaintext, "Decrypted Successfully using AES-256-ECB");

my @keysize = ("128", "192", "256");
foreach my $ks (@keysize) {
    my $key = pack("H*", substr(sha512_256_hex(rand(1000)), 0, ($ks/4)));

    foreach my $padding (0..1) {
        my $msg = $padding ? "Padding" : "No Padding";

        SKIP: {
            skip "OpenSSL 3.x is not installed", 2 if (($major lt 3.0) && $padding);
            my $coa = Crypt::OpenSSL::AES->new($key,
                                        {
                                        cipher  => "AES-$ks-ECB",
                                        padding => $padding,
                                        });

            my $ecb = Crypt::Mode::ECB->new('AES', $padding);

            my $encrypted = $coa->encrypt("Hello World. 123");
            my $plaintext = $ecb->decrypt($encrypted, $key);

            ok($plaintext eq "Hello World. 123", "Crypt::OpenSSL::AES ($ks $msg) - Decrypted with Crypt::Mode::ECB");

            $encrypted = $ecb->encrypt("Hello World. 123", $key);
            $plaintext = $coa->decrypt($encrypted);

            ok($plaintext eq "Hello World. 123", "Crypt::Mode::ECB ($ks $msg) - Decrypted with Crypt::OpenSSL::AES");
        }
    }
}
done_testing;
