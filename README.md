# NAME

Crypt::OpenSSL::AES - A Perl wrapper around OpenSSL's AES library

# SYNOPSIS

```perl
 use Crypt::OpenSSL::AES;

 my $cipher = Crypt::OpenSSL::AES->new($key);

 or

 # Pick better keys and iv...
 my $key = pack("H*", substr(sha512_256_hex(rand(1000)), 0, ($ks/4)));
 my $iv  = pack("H*", substr(sha512_256_hex(rand(1000)), 0, 32));
 my $cipher = Crypt::OpenSSL::AES->new(
                                        $key,
                                        {
                                            cipher => 'AES-256-CBC',
                                            iv      => $iv, (16-bytes for supported ciphers)
                                            padding => 1, (0 - no padding, 1 - padding)
                                        }
                                    );

 $encrypted = $cipher->encrypt($plaintext);
 $decrypted = $cipher->decrypt($encrypted);
```

# DESCRIPTION

This module implements a wrapper around OpenSSL.  Specifically, it
wraps the methods related to the US Government's Advanced
Encryption Standard (the Rijndael algorithm).  The original version
supports only AES 256 ECB (electronic codebook mode encryption).

This module is compatible with Crypt::CBC (and likely other modules
that utilize a block cipher to make a stream cipher).

This module is an alternative to the implementation provided by
Crypt::Rijndael which implements AES itself. In contrast, this module
is simply a wrapper around the OpenSSL library.

As of version 0.09 additional AES ciphers are supported.  Those are:

- Block Ciphers

    The blocksize is 16 bytes and must be padded if not a multiple of the
    blocksize.

    - AES-128-ECB, AES-192-ECB and AES-256-ECB (no IV)

        Supports padding

    - AES-128-CBC, AES-192-CBC and AES-256-CBC

        Supports padding and iv

- Stream Ciphers

    The blocksize is 1 byte. OpenSSL does not pad even if padding
    is set (the default).

    - AES-128-CFB, AES-192-CFB and AES-256-CFB

        Supports iv

    - AES-128-CTR, AES-192-CTR and AES-256-CTR

        Supports iv

    - AES-128-OFB, AES-192-OFB and AES-256-OFB

        Supports iv

- new()

    For compatibility with old versions you can simply pass the key to the
    new constructor.

    ```perl
    my $cipher = Crypt::OpenSSL::AES->new($key);

    or

    my $cipher = Crypt::OpenSSL::AES->new($key,
                    {
                        cipher  => 'AES-256-CBC',
                        iv      => $iv, (16-bytes for supported ciphers)
                        padding => 1, (0 - no padding, 1 - padding)
                    });

    # cipher
    #   AES-128-ECB, AES-192-ECB and AES-256-ECB (no IV)
    #   AES-128-CBC, AES-192-CBC and AES-256-CBC
    #   AES-128-CFB, AES-192-CFB and AES-256-CFB
    #   AES-128-CTR, AES-192-CTR and AES-256-CTR
    #   AES-128-OFB, AES-192-OFB and AES-256-OFB
    #
    # iv - 16-byte random data
    #
    # padding
    #   0 - no padding
    #   1 - padding
    ```

- $cipher->encrypt($data)

    Encrypt data. For Block Ciphers (ECB and CBC) the size of `$data`
    must be exactly `blocksize` in length (16 bytes) **or** padding must be
    enabled in the **new** constructor, otherwise this function will croak.

    For Stream ciphers (CFB, CTR or OFB) the block size is considered to
    be 1 byte and no padding is required.

    Crypt::CBC is no longer required to encrypt/decrypt data of arbitrary
    lengths.

- $cipher->decrypt($data)

    Decrypts data. For Block Ciphers (ECB and CBC) the size of `$data`
    must be exactly `blocksize` in length (16 bytes) **or** padding must be
    enabled in the **new** constructor, otherwise this function will croak.

    For Stream ciphers (CFB, CTR or OFB) the block size is considered to
    be 1 byte and no padding is required.

    Crypt::CBC is no longer required to encrypt/decrypt data of arbitrary
    lengths.

- keysize

    This method is used by Crypt::CBC to verify the key length.
    This module actually supports key lengths of 16, 24, and 32 bytes,
    but this method always returns 32 for Crypt::CBC's sake.

- blocksize

    This method is used by Crypt::CBC to check the block size.
    The blocksize for AES is always 16 bytes.

## USE WITH CRYPT::CBC

As padding is now supported for the CBC cipher, Crypt::CBC is no
longer required but supported for backward compatibility.

```perl
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
```

# SEE ALSO

[Crypt::CBC](https://metacpan.org/pod/Crypt%3A%3ACBC)

http://www.openssl.org/

http://en.wikipedia.org/wiki/Advanced\_Encryption\_Standard

http://www.csrc.nist.gov/encryption/aes/

# BUGS

Need more (and better) test cases.

# AUTHOR

Tolga Tarhan, &lt;cpan at ttar dot org>

The US Government's Advanced Encryption Standard is the Rijndael
Algorithm and was developed by Vincent Rijmen and Joan Daemen.

# COPYRIGHT AND LICENSE

Copyright (C) 2006 - 2023 DelTel, Inc.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.5 or,
at your option, any later version of Perl 5 you may have available.
