use malefic_3rd_ffi::{RtModule, RtChannel, RtResult, Body, Response};

pub struct RustModule;

impl RtModule for RustModule {
    fn name() -> &'static str { "rust_module" }
    fn new() -> Self { Self }

    fn run(&mut self, _task_id: u32, ch: &RtChannel) -> RtResult {
        match ch.recv() {
            Ok(Body::Request(_)) => {}
            Ok(_) => return RtResult::Error("expected Body::Request".into()),
            Err(e) => return RtResult::Error(e.to_string()),
        }
        RtResult::Done(Body::Response(Response {
            output: "this is rust module".to_string(),
            ..Default::default()
        }))
    }
}
