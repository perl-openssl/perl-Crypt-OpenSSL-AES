use Test::More tests => 12;
use Crypt::Mode::CBC;
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

my $key = pack("C*",0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33,0x30,0x31,0x32,0x33);

my $plaintext = pack("C*",0x41,0x42,0x43,0x44,0x41,0x42,0x43,0x44,0x41,0x42,0x43,0x44,0x41,0x42,0x43,0x44);

my $expected_enc = pack("C*", 0x9b, 0xc3, 0x7f, 0x1b, 0x92, 0x93, 0xcc, 0xf9, 0x6b, 0x64, 0x00, 0xae, 0xa3, 0xc8, 0x85, 0xbb);

# cipher is ignored with OpenSSL version < 3.0
# but AES_encrypt/AES_decrypt defaults to AES-256-ECB
my $c = Crypt::OpenSSL::AES->new($key, {cipher => 'AES-256-ECB'});

ok(($encrypted = $c->encrypt($plaintext)) eq $expected_enc, "Encrypted Successfully AES-256-ECB");

ok($c->decrypt($encrypted) eq $plaintext, "Decrypted Successfully using AES-256-ECB");

ok($c->decrypt($c->encrypt("Hello World. 123")) eq "Hello World. 123", "Simple String Encrypted/Decrypted Successfully");

my $c = Crypt::OpenSSL::AES->new($key,
                                    {
                                        cipher  => 'AES-256-CBC',
                                        iv      => 'hsui28sk2o2ksjd4',
                                    });
ok($c->decrypt($c->encrypt("Hello World. 123")) eq "Hello World. 123", "Simple String Encrypted/Decrypted Successfully with AES-256-CBC and IV");

SKIP: {

    skip "OpenSSL 3.x is not installed", 1 if ($major lt 3.0);
    skip "LibreSSL is installed", 1 if ($version_string =~ /LibreSSL/);

    $key = sha512_256_hex(rand(1000));
    $iv =  sha512_256_hex(rand(1000));

    my $cbc = Crypt::Mode::CBC->new('AES', 1);
    my $ciphertext = $cbc->encrypt("Hello World. 123", pack("H*", $key), pack("H*", substr($iv, 0, 32)));

    my $c = Crypt::OpenSSL::AES->new(pack("H*", $key),
                                    {
                                        cipher   => 'AES-256-CBC',
                                        iv          => pack("H*", substr($iv, 0, 32)),
                                        padding     => 1,
                                    });
    ok($c->decrypt($ciphertext) eq "Hello World. 123", "Decrypt Crypt::Mode::CBC encrypted data");
}

eval {
    $c->encrypt("Hello World. 123Hello World. 123");
};

unlike ($@, qr/AES: Data size must be multiple of blocksize/, "Data is a multiple of blocksize - no padding");

eval {
    $c->encrypt("Hello World. 12!!!");
};
like ($@, qr/AES: Data size must be multiple of blocksize/, "Detected no padding and data too long");

$c = Crypt::OpenSSL::AES->new(pack("H*", $key), { padding => 0, });
eval {
    $c->encrypt("Hello World. 12!!!");
};
like ($@, qr/AES: Data size must be multiple of blocksize/, "Detected no padding specified and data too long");

$c = Crypt::OpenSSL::AES->new(pack("H*", $key), { padding => 1, });
eval {
    $c->encrypt("Hello World. 12!!!");
};
unlike ($@, qr/AES: Data size must be multiple of blocksize/, "Padding and data over Block Size");

SKIP: {
    skip "OpenSSL 3.x is not installed", 1 if ($major lt 3.0);
    skip "LibreSSL is installed", 1 if ($version_string =~ /LibreSSL/);

    eval {
        $c = Crypt::OpenSSL::AES->new(pack("H*", $key),
            { cipher => "AES-192-ECB", iv => pack("H*", substr($iv, 0, 32)), });
    };
    like ($@, qr/AES-192-ECB does not use IV/, "AES-192-ECB does not use IV");
}

eval {
    $c = Crypt::OpenSSL::AES->new(pack("H*", $key), { cipher => "AES-192-ECB", });
};
unlike ($@, qr/AES-192-ECB does not use IV/, "AES-192-ECB with no IV");
done_testing;
