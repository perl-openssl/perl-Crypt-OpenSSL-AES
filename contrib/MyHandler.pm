package MyHandler;
use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Const -compile => qw(OK);
use CGI;
use Crypt::URandom qw(urandom);
use MIME::Base64 qw(decode_base64 encode_base64);

sub handler {
    my $r = shift;
    my $q = CGI->new($r);
    
    # Load module at request time as per recommended pattern
    require Crypt::OpenSSL::AES;

    my $plaintext   = $q->param('text') || "";
    my $key         = decode_base64($q->param('user_key')) || urandom(32);
    my $iv          = decode_base64($q->param('user_iv')) || urandom(16); 
    my $base64_key  = encode_base64($key);
    my $base64_iv   = encode_base64($iv);
    my $user_key    = $base64_key;
    my $user_iv     = $base64_iv;

    my $base64_result = "";

    if ($plaintext ne "") {
        # Create object INSIDE the handler for thread safety
        my $cipher = Crypt::OpenSSL::AES->new($key,
                    {
                        iv => $iv,
                        cipher => 'AES-256-CBC',
                        padding => 1,
                    });
        
        my $encrypted = $cipher->encrypt($plaintext);
        $base64_result = encode_base64($encrypted, ''); # '' removes trailing newline
    }

    $r->content_type('text/html');
    $r->print(<<"HTML");
<!DOCTYPE html>
<html>
<head>
    <title>AES Encryption Tool</title>
    <style>
        body { font-family: sans-serif; padding: 50px; background: #f0f2f5; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 500px; margin: auto; }
        input[type="text"] { width: 100%; padding: 10px; box-sizing: border-box; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; }
        input[type="submit"] { background: #1a73e8; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; width: 100%; }
        .result { background: #e8f0fe; padding: 15px; margin-top: 20px; border-radius: 4px; word-break: break-all; font-family: monospace; }
    </style>
</head>
<body>
    <div class="card">
        <h2>AES-256 Encryptor</h2>
        <p><small>MPM: Event (Threaded) | mod_perl</small></p>
        <form method="POST">
            <input type="user_key" name="user_key" placeholder="Enter the key to encrypt (default random)" value="$user_key">
            <input type="user_iv" name="user_iv" placeholder="Enter the IV to encrypt" value="$user_iv">
            <input type="text" name="text" placeholder="Enter text to encrypt" value="$plaintext">
            <input type="submit" value="Encrypt to Base64">
        </form>
HTML

    if ($base64_result) {
        $r->print(<<"RESULT");
        <div class="base64_key">
            <strong>Key (Base64):</strong><br>
            $base64_key
        </div>
        <div class="base64_iv">
            <strong>Result (Base64):</strong><br>
            $base64_iv
        </div>
        <div class="result">
            <strong>Result (Base64):</strong><br>
            $base64_result
        </div>
RESULT
    }

    $r->print("</div></body></html>");
    return Apache2::Const::OK;
}
1;
