use super::connection::WMIConnection;
use super::result_enumerator::QueryResultEnumerator;
use super::WMIResult;
use windows::core::BSTR;
use windows::Win32::System::Wmi::{WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY};

impl WMIConnection {
    /// Execute the given query and return an iterator of WMI pointers.
    pub fn exec_query_native_wrapper(
        &self,
        query: impl AsRef<str>,
    ) -> WMIResult<QueryResultEnumerator> {
        let query_language = BSTR::from("WQL");
        let query = BSTR::from(query.as_ref());

        let enumerator = unsafe {
            self.svc.ExecQuery(
                &query_language,
                &query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )?
        };

        Ok(QueryResultEnumerator::new(self, enumerator))
    }
}
