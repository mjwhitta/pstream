# PStream

## What is this?

The ruby gem will summarize or extract info from pcap files.

## How to install

```bash
$ gem install pstream
```

## Usage

```
$ pstream --help
Usage: pstream [OPTIONS] <pcap>
    -c, --ciphersuites  Show ciphersuite negotiation from ssl handshakes
    -h, --help          Display this help message
        --nocolor       Disable colorized output
    -s, --stream=NUM    Show specified stream
    -u, --udp           Use UDP
    -v, --verbose       Show backtrace when error occurs
```

## Links

- [Homepage](https://mjwhitta.github.io/pstream)
- [Source](https://gitlab.com/mjwhitta/pstream)
- [Mirror](https://github.com/mjwhitta/pstream)
- [RubyGems](https://rubygems.org/gems/pstream)

## TODO

- More features
    - Extract credentials from http traffic
        - GET/POST params
        - Basic auth headers
- Better README
- RDoc
