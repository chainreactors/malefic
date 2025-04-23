use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{FutureExt, SinkExt, StreamExt};
use malefic_proto::proto::implantpb::{Spite, Spites};

pub struct Collector {
    request_sender: UnboundedSender<bool>,
    request_receiver: UnboundedReceiver<bool>,

    response_sender: UnboundedSender<Spites>,

    data_sender: UnboundedSender<Spite>,
    data_receiver: UnboundedReceiver<Spite>,

    data: Vec<Spite>,
}

impl Collector {
    pub fn new(response_sender: UnboundedSender<Spites>) -> Self {
        let (request_sender, request_receiver) = mpsc::unbounded();
        let (data_sender, data_receiver) = mpsc::unbounded();
        Collector {
            request_sender,
            request_receiver,
            response_sender,
            data_sender,
            data_receiver,
            data: Vec::new(),
        }
    }

    pub fn get_request_sender(&self) -> UnboundedSender<bool> {
        self.request_sender.clone()
    }

    pub fn get_data_sender(&self) -> UnboundedSender<Spite> {
        self.data_sender.clone()
    }

    pub async fn run(&mut self) -> Result<(), ()> {
        #[cfg(debug_assertions)]
        let _defer = malefic_helper::Defer::new("[collector] collector exit!");
        
        loop {
            futures::select! {
                _ = self.request_receiver.next().fuse() => {
                    let data = self.get_spites();
                    let _ = self.response_sender.send(data).await;
                },
                data = self.data_receiver.next().fuse() => match data {
                    None => {
                        continue;
                    },
                    Some(data) => {
                        self.data.push(data);
                    }
                }
            }
        }
    }

    fn get_spites(&mut self) -> Spites {
        let spites = Spites {
            spites: self.data.to_vec(),
        };
        self.data.clear();
        spites
    }
}
