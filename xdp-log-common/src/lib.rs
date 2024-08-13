#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub len: usize,
}
