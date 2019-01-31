# PTRScan

A utility for scanning IP subnets for PTR records.

## Usage

```
Retrieves all PTR records of an IPv4 subnet

USAGE:
    ptrscan [OPTIONS] --cidr <cidr> --output <output_file>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --cidr <cidr>              IP network to scan in CIDR notation
    -o, --output <output_file>     Output file
    -r, --resolvers <resolvers>    Comma-separated list of DNS resolvers
                                   Default: Google DNS servers
```

Example:

```
ptrscan --cidr 8.8.8.0/24 -o google_dns_ptr.txt
```

## Future Plans

* IPv6 support?
* Accept start & end IP as alternative to CIDR?
* Accept AS number as alternative to CIDR?
* Make better use of Tokio
