#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::PerfEventArray, programs::XdpContext};
use aya_log_ebpf::info;

const TARGET_SIZE_1: usize = 430;
const TARGET_SIZE_2: usize = 66;
const SIZE_TOLERANCE: usize = 10;

#[repr(C)]
struct PacketInfo {
    size: u32,
    is_tcp: u8,
}

#[map]
static mut EVENTS: PerfEventArray<PacketInfo> = PerfEventArray::new(0);

#[xdp]
pub fn xdp_log(ctx: XdpContext) -> u32 {
    match try_xdp_log(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_log(ctx: &XdpContext) -> Result<u32, u32> {
    let packet_size = (ctx.data_end() - ctx.data()) as u32;
    
    if !is_target_size(packet_size as usize) {
        return Ok(xdp_action::XDP_PASS);
    }

    let is_tcp = unsafe {
        let protocol_offset = 23;
        if ctx.data().wrapping_add(protocol_offset) >= ctx.data_end() {
            return Err(xdp_action::XDP_ABORTED);
        }
        *(ctx.data().wrapping_add(protocol_offset) as *const u8) == 6 // TCP protocol number
    };

    let packet_info = PacketInfo {
        size: packet_size,
        is_tcp: if is_tcp { 1 } else { 0 },
    };

    unsafe {
        EVENTS.output(ctx, &packet_info, 0);
    }

    info!(
        ctx,
        "Packet captured: Size: {} bytes, Is TCP: {}",
        packet_size,
        if is_tcp { "Yes" } else { "No" }
    );

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn is_target_size(size: usize) -> bool {
    (size >= TARGET_SIZE_1.saturating_sub(SIZE_TOLERANCE) && size <= TARGET_SIZE_1.saturating_add(SIZE_TOLERANCE)) ||
    (size >= TARGET_SIZE_2.saturating_sub(SIZE_TOLERANCE) && size <= TARGET_SIZE_2.saturating_add(SIZE_TOLERANCE))
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
