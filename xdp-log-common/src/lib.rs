#![no_std]

#[repr(C)]
pub struct PacketData {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub size: u32,
    pub payload: [u8; 8],  // MAX_PACKET_SIZE is 8
}
