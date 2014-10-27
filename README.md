ssl-inspector
=============

A convenient tool for SSL cipher suites support scanning.

<pre>
Usage: ssl-inspector.rb [options]
    -a, --authentication ALGORITHM   Specify an authentication algorithm
    -b, --bits SIZE                  Specify an encryption size
    -e, --encryption ALGORITHM       Specify an encryption algorithm
    -k, --keyexchange ALGORITHM      Specify a keyexchange algorithm
    -h, --host HOST                  Specify target host
    -n, --name NAME                  Specify a cipher suite partial or full name
    -p, --port PORT                  Specify target port
    -s, --specification PROTOCOL     Specification SSLv3 or TLSv1.{0,1,2}
    -v, --verbose                    Run in verbose mode
        --help                       Show this message
</pre>
