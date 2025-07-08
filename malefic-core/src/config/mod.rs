use lazy_static::lazy_static;

lazy_static! {
    pub static ref INTERVAL: u64 = 5;
    pub static ref JITTER: f64 = 0.2 as f64;
    pub static ref NAME: String = obfstr::obfstr!("malefic").to_string();
    pub static ref PROXY: String = obfstr::obfstr!("").to_string();
    pub static ref URLS: Vec<String> = vec![
		obfstr::obfstr!("127.0.0.1:5001").to_string(),
      ];
    pub static ref KEY: Vec<u8> = obfstr::obfstr!("maliceofinternal").into();
}