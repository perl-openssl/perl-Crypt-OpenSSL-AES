FROM ubuntu:22.04

# Avoid prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install system dependencies
RUN apt-get update && apt-get install -y \
    apache2 \
    libapache2-mod-perl2 \
    libssl-dev \
    perl \
    make \
    gcc \
    git \
    bash \
    vim \
    && rm -rf /var/lib/apt/lists/*

# 2. Switch Apache to Event MPM (Threaded)
RUN a2dismod mpm_prefork && a2enmod mpm_event

# 3. Install Perl package manager and build dependencies
RUN cpan -i CGI Crypt::OpenSSL::Guess Crypt::URandom

# 4. Clone, Build, Test, and Install the module
WORKDIR /usr/src
RUN git clone https://github.com/perl-openssl/perl-Crypt-OpenSSL-AES.git
WORKDIR /usr/src/perl-Crypt-OpenSSL-AES
RUN perl Makefile.PL && make && make test && make install

# 5. Setup handler and config
# We copy the handler directly to site_perl so it's always in @INC
COPY MyHandler.pm /usr/local/lib/site_perl/
COPY apache-mod_perl.conf /etc/apache2/sites-available/000-default.conf

# Expose port 80 and start Apache
EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
