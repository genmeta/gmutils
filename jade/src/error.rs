//! Stable command diagnostics; underlying errors remain available in debug logs.
use std::fmt;

use serde_json::{Value, json};

#[derive(Debug)]
pub(crate) struct Error {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub context: Option<Value>,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(code: &'static str, message: impl fmt::Display) -> Self {
        Self {
            code,
            message: message.to_string(),
            hint: None,
            context: None,
        }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn context(mut self, context: Value) -> Self {
        self.context = Some(context);
        self
    }

    pub fn exit_code(&self) -> u8 {
        match self.code {
            "E_USAGE" => 2,
            "E_CANCELLED" => 130,
            _ => 1,
        }
    }

    pub fn json(&self) -> Value {
        let mut value = json!({"code": self.code, "message": self.message});
        if let Some(hint) = &self.hint {
            value["hint"] = hint.clone().into();
        }
        if let Some(context) = &self.context {
            value["context"] = context.clone();
        }
        value
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new("E_IO", error)
    }
}
