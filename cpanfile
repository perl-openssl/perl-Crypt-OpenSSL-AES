# This file is generated by Dist::Zilla::Plugin::CPANFile v6.030
# Do not edit this file directly. To change prereqs, edit the `dist.ini` file.

requires "Exporter" => "0";
requires "XSLoader" => "0";
requires "perl" => "5.008";

on 'build' => sub {
  requires "Crypt::OpenSSL::Guess" => "0";
};

on 'test' => sub {
  requires "Crypt::CBC" => "0";
  requires "Test::More" => "0";
};

on 'configure' => sub {
  requires "Crypt::OpenSSL::Guess" => "0";
  requires "ExtUtils::MakeMaker" => "0";
};

on 'develop' => sub {
  requires "Test::CPAN::Meta::JSON" => "0.16";
  requires "Test::Kwalitee" => "1.21";
  requires "Test::Pod" => "1.41";
  requires "Test::Spelling" => "0.12";
};
