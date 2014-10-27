ssl-inspector
=============

A convenient tool written in Ruby for SSL cipher suites support scanning.

## Disclaimer

**I will not be taken responsible for the damage that could be done using this tool. It is shared as a tool for internal security auditing.**

##Synopsis
<pre>
Usage: ssl-inspector.rb [options]
    -a, --authentication ALGORITHM   Specify an authentication algorithm
    -b, --bits [<|<=|>=|>]SIZE       Specify an encryption key size
    -e, --encryption ALGORITHM       Specify an encryption algorithm
    -h, --host HOST                  Specify target host
    -k, --keyexchange ALGORITHM      Specify a keyexchange algorithm
    -m, --mac ALGORITHM              Specify a MAC algorithm
    -n, --name NAME                  Specify a cipher suite partial or full name
    -p, --port PORT                  Specify target port
    -s, --specification PROTOCOL     Specification SSLv3 or TLSv1.{0,1,2}
    -v, --verbose                    Run in verbose mode
        --help                       Show this message
</pre>

## Usage examples

Scanning for POODLE
><pre>ruby ssl-inspector.rb -h www.domain.com -p 443 -s SSLv3 --name CBC</pre>

Checking for support of cipher suites using key size lower than 128 bits over SSLv3
><pre>ruby ssl-inspector.rb -h www.domain.com -p 443 -s SSLv3 --bits '<128'</pre>

Checking for support of cipher suites using SHA1 MAC over TLS1.0
><pre>ruby ssl-inspector.rb -h www.domain.com -p 443 -s TLSv1.0 --mac SHA</pre>

Checking for support of cipher suites not offering encryption over TLS1.0 
><pre>ruby ssl-inspector.rb -h www.domain.com -p 443 -s TLSv1.0 --encryption NULL</pre>

Checking for support of cipher using DHE key exchange with DSS encryption and 256 bits key size over TLS1.2
><pre>ruby ssl-inspector.rb -h www.domain.com -p 443 -s TLSv1.2 -k DHE -e DSS -b 256</pre>

