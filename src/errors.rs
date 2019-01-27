pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "{}: {}", reason, file)]
    OpenFile {
        file: String,
        reason: String,
    },
    #[fail(display = "Invalid resolver IP address: {}", _0)]
    InvalidResolverAddress(String),
    #[fail(display = "Invalid CIDR notation: {}", _0)]
    InvalidCidrNotation(String),
    #[fail(display = "{}", _0)]
    IoError(std::io::Error),
    #[fail(display = "Fatal error: Could not reach resolver")]
    ResolveError,
}

