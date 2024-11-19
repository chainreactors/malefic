// use tokio::sync::mpsc;
use async_std::channel::{Sender, Receiver};
use async_std::channel::unbounded as channel;
use futures::FutureExt;
use malefic_proto::proto::implantpb::{Spite, Spites};

pub struct Collector {
    request_sender: Sender<bool>,
    request_receiver: Receiver<bool>,

    response_sender: Sender<Spites>,

    data_sender: Sender<Spite>,
    data_receiver: Receiver<Spite>,

    data: Vec<Spite>
}

impl Collector {
    pub fn new(response_sender: Sender<Spites>) -> Self {
        let (request_sender, request_receiver) = channel();
        let (data_sender, data_receiver) = channel();
        Collector {
            request_sender,
            request_receiver,
            response_sender,
            data_sender,
            data_receiver,
            data: Vec::new()
        }
    }

    pub fn get_request_sender(&self) -> Sender<bool> {
        self.request_sender.clone()
    }

    pub fn get_data_sender(&self) -> Sender<Spite> {
        self.data_sender.clone()
    }

    pub async fn run(&mut self) -> Result<(), ()> {
        #[cfg(debug_assertions)]
        let _defer = malefic_helper::Defer::new("[collector] collector exit!");
        loop {
            futures::select! {
                _ = self.request_receiver.recv().fuse() => {
                    let data = self.get_spites();
                    let _ = self.response_sender.send(data).await;
                },
                data = self.data_receiver.recv().fuse() => match data {
                    Err(_) => {
                        continue;
                    },
                    Ok(data) => {
                        self.data.push(data);
                    }
                }
            }
        }
    }

    fn get_spites(&mut self) -> Spites {
        let spites = Spites {
            spites: self.data.to_vec()
        };
        self.data.clear();
        spites
    }
}
