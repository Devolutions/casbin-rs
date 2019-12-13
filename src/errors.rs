use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io;

#[derive(Debug)]
pub enum CasbinError {
    Io(io::Error),
    Error(&'static str),
    ParsingFailure(&'static str),
}

impl From<io::Error> for CasbinError {
    fn from(error: io::Error) -> Self {
        CasbinError::Io(error)
    }
}

impl Display for CasbinError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            CasbinError::Io(ref err) => write!(f, "Casbin error, IO error: {}", err),
            CasbinError::Error(msg) => write!(f, "Casbin error: msg={}", msg),
            CasbinError::ParsingFailure(msg) => write!(f, "Casbin error, Parsing failure: msg={}", msg),
        }
    }
}