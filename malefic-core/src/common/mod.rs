pub mod sys;
pub mod error;


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