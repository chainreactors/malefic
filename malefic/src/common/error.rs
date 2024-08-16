use thiserror::Error;
use modules::TaskError;

#[derive(Error, Debug)]
pub enum MaleficError {
    #[error(transparent)]
    Panic(#[from] anyhow::Error),

    #[error("")]
    UnpackError,

    #[error("")]
    MissBody,

    #[error("")]
    UnExceptBody,

    #[error("")]
    ModuleError,

    #[error("")]
    ModuleNotFound,

    #[error[""]]
    ExtensionNotFound,

    #[error("Task error: {0}")]
    TaskError(#[from] TaskError),

    #[error("")]
    TaskNotFound,

    #[error("")]
    TaskOperatorNotFound
}

impl MaleficError {
    pub fn id(&self) -> u32 {
        match self {
            MaleficError::Panic { .. }  => 1,
            MaleficError::UnpackError => 2,
            MaleficError::MissBody => 3,
            MaleficError::ModuleError => 4,
            MaleficError::ModuleNotFound => 5,
            MaleficError::TaskError { .. } => 6,
            MaleficError::TaskNotFound => 7,
            MaleficError::TaskOperatorNotFound => 8,
            MaleficError::ExtensionNotFound => 9,
            MaleficError::UnExceptBody => 10,
        }
    }
}

#[macro_export]
macro_rules! check_body {
    ($field:expr, $variant:path) => {{
        if $field.body.is_none() {
            Err(MaleficError::MissBody)
        } else {
            match $field.body {
                Some($variant(inner_body)) => Ok(inner_body),
                _ => Err(MaleficError::UnExceptBody),
            }
        }
    }};
}

