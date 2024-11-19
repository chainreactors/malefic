use std::sync::mpsc::channel;
use std::thread;
use malefic_prelude::scheduler::PreludeScheduler;
use malefic_proto::proto::implantpb::Spite;
use malefic_proto::proto::implantpb::spite::Body::Request;

#[async_std::test]
async fn test_run() {
    // 创建一个异步的发送和接收通道来处理结果
    let (result_sender, _result_receiver) = channel();
    let (_task_sender, task_receiver) = channel();
    // 初始化 BlockingScheduler
    let mut scheduler = PreludeScheduler::new(task_receiver, result_sender);

    // 创建一个 Whoami 模块的 Spite 请求
    let spite = Spite {
        task_id: 1,
        name: "whoami".to_string(),
        r#async: false,
        timeout: 0,
        error: 0,
        status: None,
        body: Some(Request(malefic_proto::proto::modulepb::Request::default())),
    };

    println!("spite: {:?}", spite);

    // 运行调度器并处理任务
    let result = scheduler.run(spite).await;

    println!("result: {:?}", result);

    // 检查结果是否成功
    assert!(result.is_ok());
}


#[test]
fn test_handler() {
    // 创建一个同步的发送和接收通道来处理结果
    let (task_sender, task_receiver) = channel();
    let (result_sender, result_receiver) = channel();

    // 初始化 BlockingScheduler
    let mut scheduler = PreludeScheduler::new(task_receiver, result_sender);

    // 创建一个线程来运行调度器
    let handle = thread::spawn(move || {
        scheduler.handler().unwrap();
    });

    // 发送一个 Whoami 模块的 Spite 请求
    let spite = Spite {
        task_id: 1,
        name: "whoami".to_string(),
        r#async: false,
        timeout: 0,
        error: 0,
        status: None,
        body: Some(Request(malefic_proto::proto::modulepb::Request::default())),
    };

    task_sender.send(spite).unwrap(); // 向调度器发送任务

    // 接收任务执行结果
    let result = result_receiver.recv().unwrap();

    println!("result: {:?}", result);

    // 结束调度器线程
    drop(task_sender); // 关闭发送通道，触发调度器结束
    handle.join().unwrap();
}