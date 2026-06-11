use super::{
    connection::WMIConnection, safearray::safe_array_to_vec_of_strings, Variant, WMIError,
    WMIResult,
};
use std::ptr;
use windows::core::VARIANT;
use windows::Win32::System::Ole::SafeArrayDestroy;
use windows::Win32::System::Variant::VariantClear;
use windows::Win32::System::Wmi::{
    IEnumWbemClassObject, IWbemClassObject, CIMTYPE_ENUMERATION, WBEM_FLAG_ALWAYS,
    WBEM_FLAG_NONSYSTEM_ONLY, WBEM_INFINITE,
};
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::System::Wmi::WBEM_CONDITION_FLAG_TYPE,
};

/// A wrapper around a raw pointer to IWbemClassObject, which also takes care of releasing
/// the object when dropped.
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IWbemClassWrapper {
    pub inner: IWbemClassObject,
}

impl IWbemClassWrapper {
    pub fn new(inner: IWbemClassObject) -> Self {
        Self { inner }
    }

    /// Return the names of all the properties of the given object.
    pub fn list_properties(&self) -> WMIResult<Vec<String>> {
        let p_names = unsafe {
            self.inner.GetNames(
                None,
                WBEM_CONDITION_FLAG_TYPE(WBEM_FLAG_ALWAYS.0 | WBEM_FLAG_NONSYSTEM_ONLY.0),
                ptr::null_mut(),
            )
        }?;

        let res = safe_array_to_vec_of_strings(unsafe { &*p_names });

        unsafe { SafeArrayDestroy(p_names) }?;

        res
    }

    pub fn get_property(&self, property_name: &str) -> WMIResult<Variant> {
        let name_prop = HSTRING::from(property_name);

        let mut vt_prop = VARIANT::default();

        let mut cim_type = 0;

        unsafe {
            self.inner.Get(
                PCWSTR::from_raw(name_prop.as_ptr()),
                0,
                &mut vt_prop,
                Some(&mut cim_type),
                None,
            )?;

            let property_value = Variant::from_variant(&vt_prop)?
                .convert_into_cim_type(CIMTYPE_ENUMERATION(cim_type))?;

            VariantClear(&mut vt_prop)?;

            Ok(property_value)
        }
    }

    pub fn path(&self) -> WMIResult<String> {
        self.get_property("__Path").and_then(Variant::try_into)
    }

    pub fn class(&self) -> WMIResult<String> {
        self.get_property("__Class").and_then(Variant::try_into)
    }
}

pub struct QueryResultEnumerator<'a> {
    _wmi_con: &'a WMIConnection,
    p_enumerator: IEnumWbemClassObject,
}

impl<'a> QueryResultEnumerator<'a> {
    pub fn new(wmi_con: &'a WMIConnection, p_enumerator: IEnumWbemClassObject) -> Self {
        Self {
            _wmi_con: wmi_con,
            p_enumerator,
        }
    }
}

impl<'a> Iterator for QueryResultEnumerator<'a> {
    type Item = WMIResult<IWbemClassWrapper>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut objs = [None; 1];
        let mut return_value = 0;

        let res = unsafe {
            self.p_enumerator
                .Next(WBEM_INFINITE, &mut objs, &mut return_value)
        };

        if let Err(e) = res.ok() {
            return Some(Err(e.into()));
        }

        if return_value == 0 {
            return None;
        }

        let mut objs = objs.into_iter();
        let pcls_ptr = objs.next().unwrap().ok_or(WMIError::NullPointerResult);

        match pcls_ptr {
            Err(e) => Some(Err(e)),
            Ok(pcls_ptr) => Some(Ok(IWbemClassWrapper::new(pcls_ptr))),
        }
    }
}
