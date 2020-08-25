use diesel;
use encryption;
use error::CommonError::*;
use std::error;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum CommonError {
    NotFound(Option<String>),
    TooFewResults(Option<String>),
    CouldNotAuthenticate(Option<String>),
    Misconfiguration(Option<String>),
    LibraryError(Option<String>),
    Duplicate(Option<String>),
    RecordNotSaved(Option<String>),
    FailedVerification(Option<String>),
}

pub type CommonResult<T> = Result<T, CommonError>;

impl fmt::Display for CommonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NotFound(ref error) => write!(f, "{:?}", error),
            LibraryError(ref error) => write!(f, "{:?}", error),
            TooFewResults(ref error) => write!(f, "{:?}", error),
            CouldNotAuthenticate(ref error) => write!(f, "{:?}", error),
            Misconfiguration(ref error) => write!(f, "{:?}", error),
            Duplicate(ref error) => write!(f, "{:?}", error),
            RecordNotSaved(ref error) => write!(f, "{:?}", error),
            FailedVerification(ref error) => write!(f, "{:?}", error),
        }
    }
}

impl error::Error for CommonError {
    fn description(&self) -> &str {
        "General Errors"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl From<diesel::result::Error> for CommonError {
    fn from(err: diesel::result::Error) -> CommonError {
        match err {
            diesel::result::Error::NotFound => {
                CommonError::NotFound(Some("Diesel Error".to_string()))
            }
            diesel::result::Error::InvalidCString(_) => {
                CommonError::LibraryError(Some("Diesel InvalidCString".to_string()))
            }
            diesel::result::Error::DatabaseError(_, _) => {
                CommonError::LibraryError(Some("Diesel DatabaseError".to_string()))
            }
            diesel::result::Error::QueryBuilderError(_) => {
                CommonError::LibraryError(Some("Diesel QueryBuilderError".to_string()))
            }
            diesel::result::Error::DeserializationError(_) => {
                CommonError::LibraryError(Some("Diesel DeserializationError".to_string()))
            }
            diesel::result::Error::SerializationError(_) => {
                CommonError::LibraryError(Some("Diesel SerializationError".to_string()))
            }
            diesel::result::Error::RollbackTransaction => {
                CommonError::LibraryError(Some("Diesel RollbackTransaction".to_string()))
            }
            diesel::result::Error::AlreadyInTransaction => {
                CommonError::LibraryError(Some("Diesel AlreadyInTransaction".to_string()))
            }
            diesel::result::Error::__Nonexhaustive => {
                CommonError::LibraryError(Some("Diesel __Nonexhaustive".to_string()))
            }
        }
    }
}

impl From<encryption::miscreant::Error> for CommonError {
    fn from(_err: encryption::miscreant::Error) -> CommonError {
        CommonError::LibraryError(Some(
            "Miscreant Error. Could be anything but probably truncated data.".to_string(),
        ))
    }
}

impl From<base64::DecodeError> for CommonError {
    fn from(_err: base64::DecodeError) -> CommonError {
        CommonError::LibraryError(Some("base64 Error.".to_string()))
    }
}

// This should be fleshed out at some point but not needed at the moment.
impl From<std::io::Error> for CommonError {
    fn from(_err: std::io::Error) -> CommonError {
        CommonError::LibraryError(Some("IO Resource Error.".to_owned()))
    }
}
