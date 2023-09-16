# NAME

Crypt::OpenSSL::AES - A Perl wrapper around OpenSSL's AES library

# SYNOPSIS

```perl
 use Crypt::OpenSSL::AES;

 my $cipher = new Crypt::OpenSSL::AES($key);

 $encrypted = $cipher->encrypt($plaintext)
 $decrypted = $cipher->decrypt($encrypted)
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

- $cipher->encrypt($data)

    Encrypt data. The size of `$data` must be exactly `blocksize` in
    length (16 bytes), otherwise this function will croak.

    You should use Crypt::CBC or something similar to encrypt/decrypt data
    of arbitrary lengths.

- $cipher->decrypt($data)

    Decrypts `$data`. The size of `$data` must be exactly `blocksize` in
    length (16 bytes), otherwise this function will croak.

    You should use Crypt::CBC or something similar to encrypt/decrypt data
    of arbitrary lengths.

- keysize

    This method is used by Crypt::CBC to verify the key length.
    This module actually supports key lengths of 16, 24, and 32 bytes,
    but this method always returns 32 for Crypt::CBC's sake.

- blocksize

    This method is used by Crypt::CBC to check the block size.
    The blocksize for AES is always 16 bytes. 

## USE WITH CRYPT::CBC

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
