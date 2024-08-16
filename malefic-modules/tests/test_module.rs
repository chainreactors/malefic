// use std::collections::HashMap;
// use tokio::sync::mpsc;
// use tokio::time::{timeout, Duration};
// use modules::Module;
// use malefic_helper::protobuf::implantpb::*;
// use malefic_helper::protobuf::implantpb::spite::Body;

// macro_rules! module_test {
//     ($module:ty, $request:expr) => {{
//         use tokio::sync::mpsc;
//         use tokio::time::{timeout, Duration};

//         // 创建模块实例
//         let mut module_instance = <$module as Module>::new().new_instance();
//         // 发送请求
//         module_instance.sender().send($request).await.unwrap();
//         // 创建结果接收器
//         let (sender, receiver) = mpsc::channel(1);
//         // 运行模块并等待结果
//         let run_result = timeout(Duration::from_secs(5), module_instance.run(1, sender))
//             .await
//             .expect("run 方法超时")
//             .expect("run 方法执行出错");

//         // 可选：打印运行结果
//         dbg!(&run_result);

//         // 返回运行结果
//         run_result
//     }};
// }

// #[tokio::test]
// async fn test_pwd() {
//     let request = spite::Body::Request(Request{
//         name: "ls".to_string(),
//         input: ".".to_string(),
//         args: vec![],
//         params: HashMap::new(),
//     });

//     let result = module_test!(modules::fs::pwd::Pwd, request);

//     match result.body {
//         Body::Response(response) => {
//             assert!(!response.output.is_empty(), "输出应该包含当前目录的路径");
//         }
//         _ => panic!("期望得到 Response 类型的 body"),
//     }
// }


// #[tokio::test]
// async fn test_ls() {
//     let request = spite::Body::Request(Request{
//         name: "ls".to_string(),
//         input: ".".to_string(),
//         args: vec![],
//         params: HashMap::new(),
//     });

//     let result = module_test!(modules::fs::ls::Ls, request);

//     match result.body {
//         Body::LsResponse(response) => {
//             assert!(!response.files.is_empty(), "输出应该包含当前目录的文件列表");
//         }
//         _ => panic!("期望得到 Response 类型的 body"),
//     }
// }
