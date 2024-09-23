#[macro_export]
macro_rules! check_request {
    ($receiver:expr, $variant:path) => {
        match $receiver.recv().await {
            Ok($variant(request)) => Ok(request),
            _ => Err(crate::TaskError::NotExpectBody)
        }
    };
}

#[macro_export]
macro_rules! check_field {
    ($field:expr) => {
        if $field.is_empty() {
            Err($crate::TaskError::FieldRequired { msg: stringify!($field).to_string()})
        }else{
            Ok($field)
        }
    };
    ($field:expr, $len:expr) => {
        if $field.len() != $len {
            Err($crate::TaskError::FieldLengthMismatch {
                msg: format!("{} expected length {}", stringify!($field), $len)
            })
        } else {
            Ok($field)
        }
    };
}

#[macro_export]
macro_rules! check_field_optional {
    ($field:expr) => {
        match $field {
            Some(field) => Ok(field),
            None => Err($crate::TaskError::FieldRequired { msg: stringify!($field).to_string()})
        }
    };
    ($field:expr, $len:expr) => {
        if $field.len() != $len {
            Err($crate::TaskError::FieldLengthMismatch {
                msg: format!("{} expected length {}", stringify!($field), $len)
            })
        } else {
            Ok($field)
        }
    };
}


#[macro_export]
macro_rules! to_error {
    ($expr:expr) => {
        $expr.map_err(|e| anyhow::Error::msg(e))
    };
}

#[macro_export]
macro_rules! register_module {
    ($map:expr, $feature:literal, $module:ty) => {
        #[cfg(feature = $feature)]
        {
            let module_name = <$module as Module>::name();
            let module_instance = <$module as Module>::new();
            $map.insert(module_name.to_string(), Box::new(module_instance));
        }
    };
}
