use Test::More tests => 1;
use Crypt::CBC;

my $plaintext = "This is a test!!";
my $password = "qwerty123";
my $cipher = Crypt::CBC->new(
    -key    => $password,
    -cipher => "Crypt::OpenSSL::AES",
    -pbkdf  => 'pbkdf2',
);

my $encrypted = $cipher->encrypt($plaintext);
my $decrypted = $cipher->decrypt($encrypted);
like($decrypted, qr/This is a test!!/, "Correctly decrypted via Crypt::CBC");
done_testing;
