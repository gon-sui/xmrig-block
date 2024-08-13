#![no_std]

#[repr(C)]
pub struct PacketInfo {
    pub size: u32,
    pub is_tcp: u8,
}
