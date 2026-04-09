use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};

use malefic_module::MaleficModule;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::{Spite, Spites};
use malefic_scheduler::TaskOperator;

pub struct MaleficChannel {
    pub data_sender: UnboundedSender<Spite>,
    pub request_sender: UnboundedSender<bool>,
    pub response_receiver: UnboundedReceiver<Spites>,
    pub scheduler_task_sender: UnboundedSender<(bool, u32, Box<MaleficModule>, Body)>,
    pub scheduler_task_ctrl: UnboundedSender<(u32, TaskOperator)>,
}
