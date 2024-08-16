use lazy_static::lazy_static;
lazy_static! (
	pub static ref INTERVAL: u64 = 1000;
	pub static ref JITTER: u64 = 10;
	pub static ref NAME: String = obfstr::obfstr!("malefic").to_string();
	pub static ref PROXY: String = obfstr::obfstr!("").to_string();
	pub static ref CA: String = obfstr::obfstr!("").to_string();
	pub static ref URLS: Vec<(String, u16)> = vec![
		(obfstr::obfstr!("127.0.0.1").to_string(), 5001),
	];
);