use ExtUtils::MakeMaker;
use Config;

my $lib = '-lcrypto';
my $inc = '';
my $nul = $^O eq 'MSWin32' ? 'nul' : '/dev/null';
if (my $dir = $ENV{OPENSSL_PREFIX}) {
  $lib = "-L$dir/lib -lcrypto";
  $inc = "-I$dir/include";
}
elsif ($ENV{OPENSSL_LIB}) {
  $lib = $ENV{OPENSSL_LIB};
  $inc = $ENV{OPENSSL_INCLUDE};
}
elsif (`pkg-config --modversion libcrypto 2>$nul`) {
  $lib = `pkg-config --libs libcrypto 2> $nul`;
  $inc = `pkg-config --cflags libcrypto 2> $nul`;
}
elsif ($^O eq 'MSWin32') {
  $lib = '-llibeay32' if $Config{cc} =~ /cl/;
  $lib = '-leay32'    if $Config{cc} =~ /gcc/;
}

WriteMakefile(
    NAME              => 'Crypt::OpenSSL::AES',
    VERSION_FROM      => 'lib/Crypt/OpenSSL/AES.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ABSTRACT_FROM     => 'lib/Crypt/OpenSSL/AES.pm',
    AUTHOR            => 'Tolga Tarhan',
    LIBS              => [ $lib ],
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => "-I. $inc",
    MIN_PERL_VERSION  => '5.006002',
    META_MERGE        => {
      resources => {
        repository => 'https://github.com/kmx/perl-Crypt-OpenSSL-AES',
      },
    },
    dist => { TARFLAGS => '--owner=0 --group=0 -cvf' }, 
);
