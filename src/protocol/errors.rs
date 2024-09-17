#[derive(Debug)]

pub enum ExtractStartConnectionHeaderError {
    InvalidAddressType(u8),
    InvalidConnectionHeader,
}

impl std::fmt::Display for ExtractStartConnectionHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ExtractStartConnectionHeaderError::InvalidAddressType(at) => {
                write!(f, "invalid address type: {}", at)
            }
            ExtractStartConnectionHeaderError::InvalidConnectionHeader => {
                write!(f, "invalid connection header")
            }
        }
    }
}

impl std::error::Error for ExtractStartConnectionHeaderError {}
