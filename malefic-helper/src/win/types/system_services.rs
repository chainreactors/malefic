#[repr(C)]
pub struct BASE_RELOCATION_BLOCK {
    pub PageAddress: u32,
    pub BlockSize: u32
}

#[repr(C)]
pub struct BASE_RELOCATION_ENTRY {
    pub Offset: u16,
    pub Type: u16 
}