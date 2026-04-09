use super::result_enumerator::IWbemClassWrapper;
use super::utils::wide_rust_to_c_string;
use super::variant::Variant;
use super::{WMIConnection, WMIError, WMIResult};
use windows::core::{BSTR, PCWSTR};
use windows::Win32::System::Wmi;
use windows::Win32::System::Wmi::IWbemClassObject;

pub struct WmiExecParam {
    pub key: String,
    pub value: Variant,
}

impl WMIConnection {
    pub fn get_object(&self, name: &str) -> WMIResult<IWbemClassObject> {
        let mut wmi_object = None;
        unsafe {
            self.svc.GetObject(
                &BSTR::from(name),
                Wmi::WBEM_FLAG_RETURN_WBEM_COMPLETE,
                None,
                Some(&mut wmi_object),
                None,
            )
        }?;

        Ok(wmi_object
            .ok_or_else(|| WMIError::SerdeError(format!("object {} is not found", name)))?)
    }

    pub fn exec_method(
        &self,
        class_name: &str,
        method_name: &str,
        params: &[WmiExecParam],
    ) -> WMIResult<Option<IWbemClassWrapper>> {
        unsafe {
            let mut in_params_class: Option<IWbemClassObject> = None;
            let object = self.get_object(class_name)?;
            object.GetMethod(
                PCWSTR::from_raw(wide_rust_to_c_string(method_name).as_ptr()),
                0,
                &mut in_params_class,
                std::ptr::null_mut(),
            )?;
            let in_params_class = in_params_class
                .ok_or_else(|| WMIError::SerdeError("in params class is none".into()))?;
            let in_params = in_params_class.SpawnInstance(0)?;
            for param in params {
                in_params.Put(
                    PCWSTR::from_raw(wide_rust_to_c_string(&param.key).as_ptr()),
                    0,
                    &Variant::to_variant(&param.value)?,
                    0,
                )?;
            }
            let mut out_params = None;
            self.svc.ExecMethod(
                &BSTR::from(class_name),
                &BSTR::from(method_name),
                Default::default(),
                None,
                &in_params,
                Some(&mut out_params),
                None,
            )?;
            match out_params {
                None => Ok(None),
                Some(out) => Ok(Some(IWbemClassWrapper::new(out))),
            }
        }
    }
}
