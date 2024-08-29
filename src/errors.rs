use std::fmt;
use tokio::io;

#[derive(Debug)]
pub struct NotImplementedError;

impl fmt::Display for NotImplementedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "This functionality is not implemented yet")
    }
}

impl std::error::Error for NotImplementedError {}

pub fn not_implemented<T>() -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::Other, NotImplementedError))
}
