use super::{
    result_enumerator::IWbemClassWrapper, safearray::safe_array_to_vec, WMIError, WMIResult,
};
use std::convert::TryFrom;
use windows::core::{IUnknown, Interface, BSTR, VARIANT};
use windows::Win32::Foundation::{VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::System::Com::{SAFEARRAY, SAFEARRAYBOUND};
use windows::Win32::System::Ole::{SafeArrayCreate, SafeArrayPutElement};
use windows::Win32::System::Variant::*;
use windows::Win32::System::Wmi::{self, IWbemClassObject, CIMTYPE_ENUMERATION};

#[derive(Debug, PartialEq)]
pub enum Variant {
    Empty,
    Null,

    String(String),

    I1(i8),
    I2(i16),
    I4(i32),
    I8(i64),

    R4(f32),
    R8(f64),

    Bool(bool),

    UI1(u8),
    UI2(u16),
    UI4(u32),
    UI8(u64),

    Array(Vec<Variant>),

    /// Temporary variant used internally
    Unknown(IUnknownWrapper),
    Object(IWbemClassWrapper),
}

// The `cast_num` macro is used to convert a numerical variable to a variant of the given CIMTYPE.
macro_rules! cast_num {
    ($var:ident, $cim_type: ident) => {
        if $cim_type == Wmi::CIM_UINT8 {
            Ok(Variant::UI1($var as u8))
        } else if $cim_type == Wmi::CIM_UINT16 {
            Ok(Variant::UI2($var as u16))
        } else if $cim_type == Wmi::CIM_UINT32 {
            Ok(Variant::UI4($var as u32))
        } else if $cim_type == Wmi::CIM_UINT64 {
            Ok(Variant::UI8($var as u64))
        } else if $cim_type == Wmi::CIM_SINT8 {
            Ok(Variant::I1($var as i8))
        } else if $cim_type == Wmi::CIM_SINT16 {
            Ok(Variant::I2($var as i16))
        } else if $cim_type == Wmi::CIM_SINT32 {
            Ok(Variant::I4($var as i32))
        } else if $cim_type == Wmi::CIM_SINT64 {
            Ok(Variant::I8($var as i64))
        } else if $cim_type == Wmi::CIM_REAL32 {
            Ok(Variant::R4($var as f32))
        } else if $cim_type == Wmi::CIM_REAL64 {
            Ok(Variant::R8($var as f64))
        } else if $cim_type == Wmi::CIM_CHAR16 {
            Ok(Variant::String(String::from_utf16(&[$var as u16])?))
        } else {
            Err(WMIError::ConvertVariantError(format!(
                "Value {:?} cannot be turned into a CIMTYPE {:?}",
                $var, $cim_type,
            )))
        }
    };
}

pub trait FromVariant {
    fn from_variant(variant: &Variant) -> Option<Self>
    where
        Self: Sized;
}
impl FromVariant for String {
    fn from_variant(variant: &Variant) -> Option<Self> {
        match variant {
            Variant::String(value) => Some(value.clone()),
            _ => None,
        }
    }
}

fn create_variant_from_strings(params: &[String]) -> WMIResult<VARIANT> {
    unsafe {
        let mut rgsa_bounds = vec![SAFEARRAYBOUND::default(); 1];
        rgsa_bounds[0].cElements = params.len() as u32;
        rgsa_bounds[0].lLbound = 0;
        let psa: *mut SAFEARRAY = SafeArrayCreate(VT_BSTR, 1, rgsa_bounds.as_ptr());
        if psa.is_null() {
            return Err(WMIError::SerdeError("Failed to create SAFEARRAY.".into()));
        }
        for (i, s) in params.iter().enumerate() {
            let bstr: BSTR = BSTR::from(s);
            SafeArrayPutElement(psa, &mut (i as i32), bstr.as_ptr() as *const _)?;
        }
        let variant = windows_core::imp::VARIANT {
            Anonymous: windows_core::imp::VARIANT_0 {
                Anonymous: windows_core::imp::VARIANT_0_0 {
                    vt: VT_BSTR.0 | VT_ARRAY.0,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: windows_core::imp::VARIANT_0_0_0 {
                        parray: psa as *mut _,
                    },
                },
            },
        };
        Ok(VARIANT::from_raw(variant))
    }
}

impl Variant {
    /// Create a `Variant` instance from a raw `VARIANT`.
    ///
    /// # Safety
    ///
    /// This function is unsafe as it is the caller's responsibility to ensure that the VARIANT is correctly initialized.
    pub fn from_variant(vt: &VARIANT) -> WMIResult<Variant> {
        let vt = vt.as_raw();
        let variant_type = unsafe { vt.Anonymous.Anonymous.vt };

        // variant_type has two 'forms':
        // 1. A simple type like `VT_BSTR` .
        // 2. An array of certain type like `VT_ARRAY | VT_BSTR`.
        if variant_type & VT_ARRAY.0 == VT_ARRAY.0 {
            let array = unsafe {
                vt.Anonymous.Anonymous.Anonymous.parray
                    as *const windows::Win32::System::Com::SAFEARRAY
            };

            let item_type = VARENUM(variant_type & VT_TYPEMASK.0);

            return Ok(Variant::Array(unsafe {
                safe_array_to_vec(&*array, item_type)?
            }));
        }

        // See https://msdn.microsoft.com/en-us/library/cc237865.aspx for more info.
        let variant_value = match VARENUM(variant_type) {
            VT_BSTR => {
                let bstr_ptr = unsafe { BSTR::from_raw(vt.Anonymous.Anonymous.Anonymous.bstrVal) };
                let bstr_as_str = bstr_ptr.to_string();
                // We don't want to be the ones freeing the BSTR.
                let _ = bstr_ptr.into_raw();
                Variant::String(bstr_as_str)
            }
            VT_I1 => {
                let num = unsafe { vt.Anonymous.Anonymous.Anonymous.cVal };
                Variant::I1(num as _)
            }
            VT_I2 => {
                let num: i16 = unsafe { vt.Anonymous.Anonymous.Anonymous.iVal };
                Variant::I2(num)
            }
            VT_I4 => {
                let num: i32 = unsafe { vt.Anonymous.Anonymous.Anonymous.lVal };
                Variant::I4(num)
            }
            VT_I8 => {
                let num: i64 = unsafe { vt.Anonymous.Anonymous.Anonymous.llVal };
                Variant::I8(num)
            }
            VT_R4 => {
                let num: f32 = unsafe { vt.Anonymous.Anonymous.Anonymous.fltVal };
                Variant::R4(num)
            }
            VT_R8 => {
                let num: f64 = unsafe { vt.Anonymous.Anonymous.Anonymous.dblVal };
                Variant::R8(num)
            }
            VT_BOOL => {
                let value = unsafe { vt.Anonymous.Anonymous.Anonymous.boolVal };
                match VARIANT_BOOL(value) {
                    VARIANT_FALSE => Variant::Bool(false),
                    VARIANT_TRUE => Variant::Bool(true),
                    _ => return Err(WMIError::ConvertBoolError(value)),
                }
            }
            VT_UI1 => {
                let num: u8 = unsafe { vt.Anonymous.Anonymous.Anonymous.bVal };
                Variant::UI1(num)
            }
            VT_UI2 => {
                let num: u16 = unsafe { vt.Anonymous.Anonymous.Anonymous.uiVal };
                Variant::UI2(num)
            }
            VT_UI4 => {
                let num: u32 = unsafe { vt.Anonymous.Anonymous.Anonymous.ulVal };
                Variant::UI4(num)
            }
            VT_UI8 => {
                let num: u64 = unsafe { vt.Anonymous.Anonymous.Anonymous.ullVal };
                Variant::UI8(num)
            }
            VT_EMPTY => Variant::Empty,
            VT_NULL => Variant::Null,
            VT_UNKNOWN => {
                let ptr = unsafe {
                    IUnknown::from_raw_borrowed(&vt.Anonymous.Anonymous.Anonymous.punkVal)
                };
                let ptr = ptr.cloned().ok_or(WMIError::NullPointerResult)?;
                Variant::Unknown(IUnknownWrapper::new(ptr))
            }
            _ => return Err(WMIError::ConvertError(variant_type)),
        };

        Ok(variant_value)
    }

    pub fn to_variant(vt: &Variant) -> WMIResult<VARIANT> {
        let v = match vt {
            Variant::Empty => VARIANT::default(),
            Variant::Null => VARIANT::default(),
            Variant::String(val) => VARIANT::from(BSTR::from(val.as_str())),
            Variant::I1(val) => VARIANT::from(*val),
            Variant::I2(val) => VARIANT::from(*val),
            Variant::I4(val) => VARIANT::from(*val),
            Variant::I8(val) => VARIANT::from(*val),
            Variant::R4(val) => VARIANT::from(*val),
            Variant::R8(val) => VARIANT::from(*val),
            Variant::Bool(val) => VARIANT::from(*val),
            Variant::UI1(val) => VARIANT::from(*val),
            Variant::UI2(val) => VARIANT::from(*val),
            Variant::UI4(val) => VARIANT::from(*val),
            Variant::UI8(val) => VARIANT::from(*val),
            Variant::Array(val) => {
                let a: Vec<String> = val
                    .into_iter()
                    .map(|item| match item {
                        Variant::String(s) => s.to_string(),
                        _ => unreachable!(),
                    })
                    .collect();
                create_variant_from_strings(&a)?
            }
            _ => return Err(WMIError::SerdeError("unknown type".into())),
        };
        Ok(v)
    }

    pub fn to_vec<T: 'static>(&self) -> Vec<T>
    where
        T: Clone + FromVariant,
    {
        match self {
            Variant::Array(variants) => {
                let mut result = Vec::new();
                for variant in variants {
                    if let Some(value) = T::from_variant(variant) {
                        result.push(value);
                    }
                }
                result
            }
            _ => Vec::new(),
        }
    }

    /// Convert the variant it to a specific type.
    pub fn convert_into_cim_type(self, cim_type: CIMTYPE_ENUMERATION) -> WMIResult<Self> {
        if cim_type == Wmi::CIM_EMPTY {
            return Ok(Variant::Null);
        }

        if (Wmi::CIM_FLAG_ARRAY.0 & cim_type.0) != 0 {
            return match self {
                Variant::Array(arr) => Variant::Array(arr)
                    .convert_into_cim_type(CIMTYPE_ENUMERATION(cim_type.0 & 0xff)),
                Variant::Empty | Variant::Null => Ok(Variant::Array(vec![])),
                not_array => {
                    Ok(Variant::Array(vec![not_array.convert_into_cim_type(
                        CIMTYPE_ENUMERATION(cim_type.0 & 0xff),
                    )?]))
                }
            };
        }

        let converted_variant = match self {
            Variant::Empty => Variant::Empty,
            Variant::Null => Variant::Null,
            Variant::I1(n) => cast_num!(n, cim_type)?,
            Variant::I2(n) => cast_num!(n, cim_type)?,
            Variant::I4(n) => cast_num!(n, cim_type)?,
            Variant::I8(n) => cast_num!(n, cim_type)?,
            Variant::R4(f) => cast_num!(f, cim_type)?,
            Variant::R8(f) => cast_num!(f, cim_type)?,
            Variant::UI1(n) => cast_num!(n, cim_type)?,
            Variant::UI2(n) => cast_num!(n, cim_type)?,
            Variant::UI4(n) => cast_num!(n, cim_type)?,
            Variant::UI8(n) => cast_num!(n, cim_type)?,
            Variant::Bool(b) => {
                if cim_type == Wmi::CIM_BOOLEAN {
                    Variant::Bool(b)
                } else {
                    return Err(WMIError::ConvertVariantError(format!(
                        "A boolean Variant cannot be turned into a CIMTYPE {:?}",
                        cim_type,
                    )));
                }
            }
            Variant::String(s) => match cim_type {
                Wmi::CIM_STRING | Wmi::CIM_CHAR16 => Variant::String(s),
                Wmi::CIM_REAL64 => Variant::R8(s.parse()?),
                Wmi::CIM_REAL32 => Variant::R4(s.parse()?),
                Wmi::CIM_UINT64 => Variant::UI8(s.parse()?),
                Wmi::CIM_SINT64 => Variant::I8(s.parse()?),
                Wmi::CIM_UINT32 => Variant::UI4(s.parse()?),
                Wmi::CIM_SINT32 => Variant::I4(s.parse()?),
                Wmi::CIM_UINT16 => Variant::UI2(s.parse()?),
                Wmi::CIM_SINT16 => Variant::I2(s.parse()?),
                Wmi::CIM_UINT8 => Variant::UI1(s.parse()?),
                Wmi::CIM_SINT8 => Variant::I1(s.parse()?),
                _ => Variant::String(s),
            },
            Variant::Array(variants) => {
                let converted_variants = variants
                    .into_iter()
                    .map(|variant| variant.convert_into_cim_type(cim_type))
                    .collect::<Result<Vec<_>, WMIError>>()?;

                Variant::Array(converted_variants)
            }
            Variant::Unknown(u) => {
                if cim_type == Wmi::CIM_OBJECT {
                    Variant::Object(u.to_wbem_class_obj()?)
                } else {
                    return Err(WMIError::ConvertVariantError(format!(
                        "A unknown Variant cannot be turned into a CIMTYPE {:?}",
                        cim_type,
                    )));
                }
            }
            Variant::Object(o) => Variant::Object(o),
        };

        Ok(converted_variant)
    }
}

/// A wrapper around the [`IUnknown`] interface.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
pub struct IUnknownWrapper {
    inner: IUnknown,
}

impl IUnknownWrapper {
    pub fn new(ptr: IUnknown) -> Self {
        IUnknownWrapper { inner: ptr }
    }

    pub fn to_wbem_class_obj(&self) -> WMIResult<IWbemClassWrapper> {
        Ok(IWbemClassWrapper {
            inner: self.inner.cast::<IWbemClassObject>()?,
        })
    }
}

macro_rules! impl_try_from_variant {
    ($target_type:ty, $variant_type:ident) => {
        impl TryFrom<Variant> for $target_type {
            type Error = WMIError;

            fn try_from(value: Variant) -> Result<$target_type, Self::Error> {
                match value {
                    Variant::$variant_type(item) => Ok(item),
                    other => Err(WMIError::ConvertVariantError(format!(
                        "Variant {:?} cannot be turned into a {}",
                        &other,
                        stringify!($target_type)
                    ))),
                }
            }
        }
    };
}

impl_try_from_variant!(String, String);
impl_try_from_variant!(i8, I1);
impl_try_from_variant!(i16, I2);
impl_try_from_variant!(i32, I4);
impl_try_from_variant!(i64, I8);
impl_try_from_variant!(u8, UI1);
impl_try_from_variant!(u16, UI2);
impl_try_from_variant!(u32, UI4);
impl_try_from_variant!(u64, UI8);
impl_try_from_variant!(f32, R4);
impl_try_from_variant!(f64, R8);
impl_try_from_variant!(bool, Bool);
