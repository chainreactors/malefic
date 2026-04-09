#![allow(unused_imports)]

pub use anyhow::anyhow;
pub use malefic_gateway::module_impl;
pub use malefic_module::{
    check_field, check_optional, check_request, debug, register_module, to_error,
};
pub use malefic_module::{
    Input, MaleficBundle, MaleficModule, Module, ModuleImpl, ModuleResult, Output, TaskError,
    TaskResult,
};
pub use malefic_proto::proto::implantpb::spite::Body;
pub use malefic_proto::proto::implantpb::{Spite, Spites};
pub use malefic_proto::proto::modulepb::Response;
