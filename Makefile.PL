use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Crypt::OpenSSL::AES',
    VERSION_FROM      => 'lib/Crypt/OpenSSL/AES.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ABSTRACT_FROM     => 'lib/Crypt/OpenSSL/AES.pm',
    AUTHOR            => 'Tolga Tarhan',
    LIBS              => ['-lcrypto'], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
    MIN_PERL_VERSION  => '5.006002',
    META_MERGE        => {
      resources => {
        repository => 'https://github.com/kmx/perl-Crypt-OpenSSL-AES',
      },
    },
    dist => { TARFLAGS => '--owner=0 --group=0 -cvf' }, 
);
