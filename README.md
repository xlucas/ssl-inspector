ssl-inspector
=============

A convenient tool written in Ruby for SSL cipher suites support scanning.

## Disclaimer

**I will not be taken responsible for the damage that could be done using this tool. It is shared as a tool for internal security auditing.**

##Installation
```bash
user@host $ wget "https://raw.githubusercontent.com/xlucas/ssl-inspector/master/bin/ssl-inspector.rb" \
-o /usr/local/bin/ssl-inspector
user@host $ chmod +x !$
```

##Synopsis
```text
Usage: ssl-inspector [options]
    -a, --authentication ALGORITHM   Specify an authentication algorithm
    -b, --bits [<|<=|=>|>]SIZE       Specify an encryption key size
    -e, --encryption ALGORITHM       Specify an encryption algorithm
    -h, --host HOST                  Specify target host
    -k, --keyexchange ALGORITHM      Specify a keyexchange algorithm
    -m, --mac ALGORITHM              Specify a MAC algorithm
    -n, --name NAME                  Specify a cipher suite partial or full name
    -p, --port PORT                  Specify target port
    -s, --specification PROTOCOL     Specification SSLv3 or TLSv1.{0,1,2}
    -v, --verbose                    Run in verbose mode
        --help                       Show this message
```

## Usage examples

Scanning for POODLE
>```ruby ssl-inspector.rb -h www.domain.com -p 443 -s SSLv3 --name CBC```

Checking for support of cipher suites using key size lower than 128 bits over SSLv3
>```ruby ssl-inspector.rb -h www.domain.com -p 443 -s SSLv3 --bits '<128'```

Checking for support of cipher suites using SHA1 MAC over TLS1.0
>```ruby ssl-inspector.rb -h www.domain.com -p 443 -s TLSv1.0 --mac SHA```

Checking for support of cipher suites not offering encryption over TLS1.0 
>```ruby ssl-inspector.rb -h www.domain.com -p 443 -s TLSv1.0 --encryption NULL```

Checking for support of cipher suites using DHE key exchange and DSS encryption with 256 bits key size over TLS1.2
>```ruby ssl-inspector.rb -h www.domain.com -p 443 -s TLSv1.2 -k DHE -e DSS -b 256```

## Requirement

Ruby 2.1 installed
