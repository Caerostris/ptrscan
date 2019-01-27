#[macro_use] extern crate clap;
#[macro_use] extern crate failure;
extern crate tokio;
extern crate trust_dns_resolver;
extern crate ipnet;
extern crate pbr;

mod errors;
use errors::{Error, Result};

use std::net::*;
use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveErrorKind;
use ipnet::Ipv4Net;
use tokio::runtime::Runtime;
use std::fs::File;
use std::io::Write;
use pbr::ProgressBar;

fn _main() -> Result<()> {
    let matches = clap_app!(ptrscan =>
        (version: "0.1")
        (author: "Caerostris <caerostris@gmail.com>")
        (about: "Retrieves all PTR records of an IPv4 address range")
        (@arg cidr: --cidr +required +takes_value
            "IP network to scan for PTR records")
        (@arg output_file: -o --output +required +takes_value "Output file")
        (@arg resolvers: -r --resolvers +takes_value
            "Comma-separated list of DNS resolvers (default: Google resolvers")
    ).get_matches();

    // TODO: allow user to pass a starting and ending IP instead of CIDR
    // parse IPv4 network specification
    let ip_net = matches.value_of("cidr").unwrap().to_string();
    let ip_net: Ipv4Net = ip_net.parse().map_err(|_|
        Error::InvalidCidrNotation(ip_net)
    )?;

    // parse command line options to create resolver
    let (resolver, background) = matches
        .value_of("resolvers")
        .map(|resolvers| Ok(AsyncResolver::new(
            resolver_config_from_string(resolvers)?,
            ResolverOpts::default()
        )))
        .unwrap_or(Ok(AsyncResolver::new(
            ResolverConfig::google(),
            ResolverOpts::default()
        )))?;

    // create a tokio runtime
    let mut runtime = Runtime::new().unwrap();
    runtime.spawn(background);

    // create futures for resolving PTR of each host in the given subnet
    let mut futures: Vec<_> = ip_net.hosts()
        .map(|host| resolver.reverse_lookup(IpAddr::V4(host)))
        .collect();

    // open output file for writing
    let output_file = matches.value_of("output_file").unwrap();
    let mut output_file = File::create(output_file)
        .map_err(|err| Error::OpenFile {
            file: output_file.to_string(),
            reason: err.to_string(),
        })?;

    let total_lookups = futures.len();
    let mut successful_lookups = 0;
    let mut failed_lookups = 0;
    let mut pb = ProgressBar::new(total_lookups as u64);

    // wait for lookups to finish and write results to file
    // TODO: surely there's a more sophisticated way to do this...
    // Is this even asynchronous?
    for future in futures.drain(..) {
        match runtime.block_on(future) {
            Ok(ptrs) => {
                pb.inc();
                successful_lookups += 1;
                for ptr in ptrs.iter()  {
                    let s_ptr = ptr.to_string();
                    let domain = s_ptr.trim_end_matches('.');
                    writeln!(output_file, "{}", domain)
                        .map_err(|err| Error::IoError(err))?;
                }
            },
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {
                    pb.inc();
                    failed_lookups += 1;
                },
                // TODO: consider error behaviour
                // Keep retrying? Silently ignore errors?
                // Just crashing seems a bit overkill.
                _ => return Err(Error::ResolveError),
            },
        }
    }

    // print stats
    pb.finish();
    print!("Total lookups: {} ", total_lookups);
    print!("Successful lookups: {} ", successful_lookups);
    println!("Failed lookups: {}", failed_lookups);

    drop(resolver);
    Ok(())
}

fn resolver_config_from_string(resolver_list: &str) -> Result<ResolverConfig> {
    let ips = resolver_list
        .split(",")
        .map(|resolver| Ok(IpAddr::V4(
            resolver.parse().map_err(|_|
                Error::InvalidResolverAddress(resolver.to_string())
            )?
        )))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let resolvers = NameServerConfigGroup::from_ips_clear(&ips, 53);
    Ok(ResolverConfig::from_parts(None, vec![], resolvers))
}

fn main() {
    if let Err(err) = _main() {
       eprintln!("{}", err);
       std::process::exit(1);
    }
}
