use strict;
use warnings;
use Test::More tests => 7;
use Crypt::Mode::CFB;
use Crypt::PRNG qw(rand);
use Crypt::Digest::SHA512_256 qw( sha512_256_hex );

BEGIN { use_ok('Crypt::OpenSSL::AES') };

my @keysize = ("128", "192", "256");
foreach my $ks (@keysize) {
    {
        my $key = pack("H*", substr(sha512_256_hex(rand(1000)), 0, ($ks/4)));
        my $iv  = pack("H*", substr(sha512_256_hex(rand(1000)), 0, 32));

        my $coa = Crypt::OpenSSL::AES->new($key,
                                        {
                                        cipher  => "AES-$ks-CFB",
                                        iv      => $iv,
                                        });

        my $ecb = Crypt::Mode::CFB->new('AES');

        my $encrypted = $coa->encrypt("Hello World. 123");
        my $plaintext = $ecb->decrypt($encrypted, $key, $iv);

        ok($plaintext eq "Hello World. 123", "Crypt::OpenSSL::AES ($ks) - Decrypted with Crypt::Mode::CFB");

        $encrypted = $ecb->encrypt("Hello World. 123", $key, $iv);
        $plaintext = $coa->decrypt($encrypted);

        ok($plaintext eq "Hello World. 123", "Crypt::Mode::CFB ($ks) - Decrypted with Crypt::OpenSSL::AES");
    }
}
done_testing;
