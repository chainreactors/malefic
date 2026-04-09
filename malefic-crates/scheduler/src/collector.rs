use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{FutureExt, SinkExt, StreamExt};
use malefic_crypto::crypto::{new_cryptor, Cryptor};
use malefic_proto::proto::implantpb::{Spite, Spites};
use prost::Message;

pub struct Collector {
    request_sender: UnboundedSender<bool>,
    request_receiver: UnboundedReceiver<bool>,

    response_sender: UnboundedSender<Spites>,

    data_sender: UnboundedSender<Spite>,
    data_receiver: UnboundedReceiver<Spite>,

    data: Vec<Vec<u8>>,
    cryptor: Cryptor,
}

impl Collector {
    pub fn new(response_sender: UnboundedSender<Spites>) -> Self {
        let (request_sender, request_receiver) = mpsc::unbounded();
        let (data_sender, data_receiver) = mpsc::unbounded();

        let mut key = vec![0u8; 32];
        let mut iv = vec![0u8; 16];
        malefic_common::random::fill(&mut key);
        malefic_common::random::fill(&mut iv);
        let cryptor = new_cryptor(key, iv);

        Collector {
            request_sender,
            request_receiver,
            response_sender,
            data_sender,
            data_receiver,
            data: Vec::new(),
            cryptor,
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
        let _defer = malefic_common::errors::Defer::new("[collector] collector exit!");

        loop {
            futures::select! {
                _ = self.request_receiver.next().fuse() => {
                    self.drain_pending_data();
                    let data = self.get_spites();
                    let _ = self.response_sender.send(data).await;
                },
                data = self.data_receiver.next().fuse() => match data {
                    None => {
                        continue;
                    },
                    Some(spite) => {
                        let plaintext = spite.encode_to_vec();
                        if let Ok(encrypted) = self.cryptor.encrypt(plaintext) {
                            self.data.push(encrypted);
                        }
                    }
                }
            }
        }
    }

    fn drain_pending_data(&mut self) {
        while let Ok(Some(spite)) = self.data_receiver.try_next() {
            let plaintext = spite.encode_to_vec();
            if let Ok(encrypted) = self.cryptor.encrypt(plaintext) {
                self.data.push(encrypted);
            }
        }
    }

    fn get_spites(&mut self) -> Spites {
        let spites = self
            .data
            .iter()
            .filter_map(|encrypted| {
                self.cryptor
                    .decrypt(encrypted.clone())
                    .ok()
                    .and_then(|bytes| Spite::decode(bytes.as_slice()).ok())
            })
            .collect();
        self.data.clear();
        self.cryptor.reset();
        Spites { spites }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use malefic_proto::proto::implantpb::{spite::Body, Empty, Status};

    fn make_spite(task_id: u32, name: &str) -> Spite {
        Spite {
            task_id,
            name: name.to_string(),
            r#async: true,
            timeout: 0,
            error: 0,
            status: Some(Status {
                task_id,
                status: 0,
                error: String::new(),
            }),
            body: Some(Body::Empty(Empty {})),
        }
    }

    /// Verify that stored data is actually encrypted (not plaintext protobuf).
    #[test]
    fn stored_data_is_encrypted() {
        let (response_sender, _response_receiver) = mpsc::unbounded();
        let mut collector = Collector::new(response_sender);

        let spite = make_spite(42, "test_module");
        let plaintext = spite.encode_to_vec();

        let encrypted = collector.cryptor.encrypt(plaintext.clone()).unwrap();
        collector.data.push(encrypted.clone());

        // Encrypted bytes must differ from plaintext
        assert_ne!(encrypted, plaintext, "stored data should not be plaintext");
        // Must not be decodable as a Spite directly
        assert!(
            Spite::decode(encrypted.as_slice()).is_err()
                || Spite::decode(encrypted.as_slice()).unwrap() != spite,
            "encrypted blob should not decode as the original Spite"
        );
    }

    /// Verify single spite encrypt-then-decrypt round-trip.
    #[test]
    fn single_spite_round_trip() {
        let (response_sender, _response_receiver) = mpsc::unbounded();
        let mut collector = Collector::new(response_sender);

        let spite = make_spite(1, "round_trip");
        let plaintext = spite.encode_to_vec();
        let encrypted = collector.cryptor.encrypt(plaintext).unwrap();
        collector.data.push(encrypted);

        let spites = collector.get_spites();
        assert_eq!(spites.spites.len(), 1);
        assert_eq!(spites.spites[0], spite);
    }

    /// Verify multiple spites are correctly encrypted and decrypted in order.
    #[test]
    fn multiple_spites_round_trip() {
        let (response_sender, _response_receiver) = mpsc::unbounded();
        let mut collector = Collector::new(response_sender);

        let items: Vec<Spite> = (0..5)
            .map(|i| make_spite(i, &format!("task_{}", i)))
            .collect();

        for spite in &items {
            let plaintext = spite.encode_to_vec();
            let encrypted = collector.cryptor.encrypt(plaintext).unwrap();
            collector.data.push(encrypted);
        }

        let spites = collector.get_spites();
        assert_eq!(spites.spites.len(), 5);
        for (i, spite) in spites.spites.iter().enumerate() {
            assert_eq!(spite, &items[i], "spite {} mismatch", i);
        }
    }

    /// After get_spites(), buffer must be empty and cryptor reset for next batch.
    #[test]
    fn get_spites_clears_buffer_and_resets_cryptor() {
        let (response_sender, _response_receiver) = mpsc::unbounded();
        let mut collector = Collector::new(response_sender);

        // Batch 1
        let spite1 = make_spite(10, "batch1");
        let encrypted = collector.cryptor.encrypt(spite1.encode_to_vec()).unwrap();
        collector.data.push(encrypted);
        let result1 = collector.get_spites();
        assert_eq!(result1.spites.len(), 1);
        assert_eq!(result1.spites[0], spite1);

        // Buffer should be empty now
        assert!(collector.data.is_empty());

        // Batch 2 should work correctly after reset
        let spite2 = make_spite(20, "batch2");
        let encrypted = collector.cryptor.encrypt(spite2.encode_to_vec()).unwrap();
        collector.data.push(encrypted);
        let result2 = collector.get_spites();
        assert_eq!(result2.spites.len(), 1);
        assert_eq!(result2.spites[0], spite2);
    }

    /// Empty collector returns empty Spites.
    #[test]
    fn empty_collector_returns_empty_spites() {
        let (response_sender, _response_receiver) = mpsc::unbounded();
        let mut collector = Collector::new(response_sender);

        let spites = collector.get_spites();
        assert!(spites.spites.is_empty());
    }

    /// Integration test: data flows through channels and is encrypted/decrypted correctly.
    #[test]
    fn channel_integration_flow() {
        futures::executor::block_on(async {
            let (response_sender, mut response_receiver) = mpsc::unbounded();
            let mut collector = Collector::new(response_sender);
            let data_sender = collector.get_data_sender();

            let expected = make_spite(99, "async_test");

            // Simulate what run() does: send data via channel, receive and encrypt
            data_sender.unbounded_send(expected.clone()).unwrap();
            let spite = collector.data_receiver.next().await.unwrap();
            let plaintext = spite.encode_to_vec();
            let encrypted = collector.cryptor.encrypt(plaintext).unwrap();
            collector.data.push(encrypted);

            // Simulate request: get_spites decrypts and sends response
            let spites = collector.get_spites();
            let _ = collector.response_sender.send(spites).await;

            let received = response_receiver.next().await.unwrap();
            assert_eq!(received.spites.len(), 1);
            assert_eq!(received.spites[0], expected);
        });
    }

    #[test]
    fn request_flush_drains_pending_data_before_responding() {
        let (response_sender, _response_receiver) = mpsc::unbounded();
        let mut collector = Collector::new(response_sender);

        let spite = make_spite(77, "flush_first");
        collector
            .data_sender
            .unbounded_send(spite.clone())
            .expect("enqueue spite");
        collector.drain_pending_data();

        let spites = collector.get_spites();
        assert_eq!(spites.spites, vec![spite]);
    }

    /// Each Collector instance uses a different random key.
    #[test]
    fn different_collectors_use_different_keys() {
        let (s1, _) = mpsc::unbounded();
        let (s2, _) = mpsc::unbounded();
        let mut c1 = Collector::new(s1);
        let mut c2 = Collector::new(s2);

        let spite = make_spite(1, "key_test");
        let plaintext = spite.encode_to_vec();
        let enc1 = c1.cryptor.encrypt(plaintext.clone()).unwrap();
        let enc2 = c2.cryptor.encrypt(plaintext).unwrap();

        // Different keys should produce different ciphertexts
        assert_ne!(
            enc1, enc2,
            "different collectors should produce different ciphertexts"
        );
    }
}
