use strict;
use warnings;
use Test::More tests => 13;
use Crypt::Mode::CBC;
use Crypt::PRNG qw(rand);
use Crypt::Digest::SHA512_256 qw( sha512_256_hex );

BEGIN { use_ok('Crypt::OpenSSL::AES') };

my @keysize = ("128", "192", "256");
foreach my $ks (@keysize) {
    my $key = pack("H*", substr(sha512_256_hex(rand(1000)), 0, ($ks/4)));
    my $iv  = pack("H*", substr(sha512_256_hex(rand(1000)), 0, 32));

    foreach my $padding (0..1) {
        {
            my $msg = $padding ? "Padding" : "No Padding";
            my $coa = Crypt::OpenSSL::AES->new($key,
                                        {
                                        cipher  => "AES-$ks-CBC",
                                        padding => $padding,
                                        iv      => $iv,
                                        });

            my $ecb = Crypt::Mode::CBC->new('AES', $padding);

            my $encrypted = $coa->encrypt("Hello World. 123");
            my $plaintext = $ecb->decrypt($encrypted, $key, $iv);

            ok($plaintext eq "Hello World. 123", "Crypt::OpenSSL::AES ($ks $msg) - Decrypted with Crypt::Mode::CBC");

            $encrypted = $ecb->encrypt("Hello World. 123", $key, $iv);
            $plaintext = $coa->decrypt($encrypted);

            ok($plaintext eq "Hello World. 123", "Crypt::Mode::CBC ($ks $msg) - Decrypted with Crypt::OpenSSL::AES");
        }
    }
}
done_testing;
