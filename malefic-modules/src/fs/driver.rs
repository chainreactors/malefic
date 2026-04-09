use crate::prelude::*;
use malefic_proto::proto::modulepb::{DriveInfo, EnumDriversResponse};

pub struct EnumDrivers {}

#[async_trait]
#[module_impl("enum_drivers")]
impl Module for EnumDrivers {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for EnumDrivers {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let _request = check_request!(receiver, Body::Request)?;
        let mut drives = vec![];

        let drive_list = malefic_sysinfo::win::driver::enum_drivers();
        for (drive_path, drive_type) in drive_list {
            drives.push(DriveInfo {
                path: drive_path,
                drive_type,
                total_size: 0,
                free_size: 0,
                file_system: "".to_string(),
            });
        }

        Ok(TaskResult::new_with_body(
            id,
            Body::EnumDriversResponse(EnumDriversResponse { drives }),
        ))
    }
}
