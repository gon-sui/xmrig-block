#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::{mem, ptr};
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, tcp::TcpHdr, udp::UdpHdr};

#[repr(C)]
struct PacketInfo {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

#[xdp]
pub fn xdp_log(ctx: XdpContext) -> u32 {
    match try_xdp_log(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_xdp_log(ctx: &XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let ether_type = unsafe { ptr::read_unaligned(ptr::addr_of!((*ethhdr).ether_type)) };

    if ether_type != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
    let src_addr = unsafe { ptr::read_unaligned(ptr::addr_of!((*ipv4hdr).src_addr)) };
    let dst_addr = unsafe { ptr::read_unaligned(ptr::addr_of!((*ipv4hdr).dst_addr)) };
    let proto = unsafe { (*ipv4hdr).proto };

    let mut packet_info = PacketInfo {
        src_ip: u32::from_be(src_addr),
        dst_ip: u32::from_be(dst_addr),
        src_port: 0,
        dst_port: 0,
        protocol: proto as u8,
    };

    let transport_header = unsafe { ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + match proto {
        IpProto::Tcp => {
            let tcphdr = transport_header as *const TcpHdr;
            packet_info.src_port = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*tcphdr).source)) });
            packet_info.dst_port = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*tcphdr).dest)) });
            TcpHdr::LEN
        },
        IpProto::Udp => {
            let udphdr = transport_header as *const UdpHdr;
            packet_info.src_port = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*udphdr).source)) });
            packet_info.dst_port = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*udphdr).dest)) });
            UdpHdr::LEN
        },
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let mut hex_payload = [0u8; 32];
    let payload_len = core::cmp::min(16, ctx.data_end() - ctx.data() - payload_offset);

    for i in 0..payload_len {
        let byte = unsafe { *ptr_at::<u8>(ctx, payload_offset + i)? };
        hex_payload[i*2] = hex_char(byte >> 4);
        hex_payload[i*2 + 1] = hex_char(byte & 0xf);
    }

    info!(
        ctx,
        "{:i}:{} → {:i}:{} {} {}",
        packet_info.src_ip,
        packet_info.src_port,
        packet_info.dst_ip,
        packet_info.dst_port,
        match packet_info.protocol {
            6 => "TCP",
            17 => "UDP",
            _ => "Unknown",
        },
        unsafe { core::str::from_utf8_unchecked(&hex_payload[..payload_len*2]) }
    );

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn hex_char(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + (n - 10),
        _ => b'0',
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
