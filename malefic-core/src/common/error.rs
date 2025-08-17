use thiserror::Error;
use malefic_proto::module::TaskError;

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
    AddonNotFound,

    #[error("Task error: {0}")]
    TaskError(#[from] TaskError),
    
    #[error("Transport: {0}")]
    TransportError(#[from] crate::transport::TransportError),
    
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
            MaleficError::AddonNotFound => 9,
            MaleficError::UnExceptBody => 10,
            MaleficError::TransportError{ .. } => 11,
        }
    }
}



