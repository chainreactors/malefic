use malefic_proto::proto::implantpb::Spite;
use malefic_proto::proto::implantpb::spite::Body::Request;
use anyhow::Result;
use malefic_prelude::autorun::Autorun;

#[test]
fn test_autorun() -> Result<(), Box<dyn std::error::Error>> {
    // 创建一组模拟的 Spite 任务
    let tasks = vec![
        Spite {
            task_id: 1,
            name: "whoami".to_string(),
            r#async: false,
            timeout: 0,
            error: 0,
            status: None,
            body: Some(Request(malefic_proto::proto::modulepb::Request::default())),
        },
        Spite {
            task_id: 2,
            name: "ps".to_string(),
            r#async: false,
            timeout: 0,
            error: 0,
            status: None,
            body: Some(Request(malefic_proto::proto::modulepb::Request::default())),
        },
    ];

    // 初始化 Autorun 实例
    let mut autorun = Autorun::new()?;

    // 执行所有任务并获取结果
    let results = autorun.execute(tasks)?;

    // 检查结果的数量
    assert_eq!(results.len(), 2);
    
    println!("results: {:#?}", results);

    Ok(())
}
