//! Razer wireless keyboard battery via 2.4G dongles (VID 0x1532, MI_02 vendor
//! interface). The dongle answers on behalf of the paired keyboard.
//!
//! Protocol (reverse-engineered, matches OpenRazer semantics for the wireless
//! keyboard transaction): 90-byte feature reports.
//!
//!   payload layout (the 90 bytes, before the report-id prefix):
//!     [0] status (0x00 for requests)
//!     [1] transaction id — per-dongle, see DONGLES below
//!     [2..4] remaining packets (0)
//!     [5] data size
//!     [6] command class
//!     [7] command id
//!     [8..88] arguments
//!     [88] CRC = XOR of bytes 2..=87
//!     [89] reserved
//!
//! Windows quirks we had to discover empirically (the Python prototype in
//! D:\Code\AI\杂项\雷蛇键盘电量工具 proved them):
//!   * SET must go as HidD_SetFeature with the 0x01 report-id prefix; GET as
//!     HidD_GetFeature with the same prefix. Output writes get ignored.
//!   * CRC is XOR over bytes 2..=87 (OpenRazer's `razer_calculate_crc`).
//!   * The device often answers BUSY (0x01) or TIMEOUT (0x04); retry until
//!     SUCCESS (0x02).
//!   * Battery level (0-255 scale) is argument[1]; charging flag is argument[1]
//!     of the 0x84 command.
//!
//! Why raw FFI instead of hidapi: the dongle's MI_02 top-level collection
//! reports `FeatureReportByteLength = 0` in HIDP_CAPS (the feature report is
//! per-report-id 92 bytes, which the caps header doesn't reflect). hidapi's
//! windows-native backend sizes its fixed feature buffer from the caps and
//! then silently exchanges zero-length reports. We open the device ourselves
//! and pass explicit-length buffers to HidD_SetFeature/GetFeature.

use crate::model::BatteryState;
use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::ptr::null_mut;

pub const RAZER_VID: u16 = 0x1532;
/// The dongle's vendor command interface (MI_02).
const VENDOR_IFACE: i32 = 2;

const CMD_CLASS_BATTERY: u8 = 0x07;
const CMD_GET_BATTERY_LEVEL: u8 = 0x80;
const CMD_GET_CHARGING_STATUS: u8 = 0x84;

const STATUS_SUCCESS: u8 = 0x02;
const RETRIES: usize = 6;
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(60);

/// Wire size of one feature report: 1 (report id) + 90 (payload).
const FEATURE_XFER: usize = 91;

/// A supported Razer 2.4G keyboard dongle.
///
/// PIDs and transaction IDs follow OpenRazer's `razerkbd_driver` (the wireless
/// keyboard families use 0x9F; the BlackWidow V3 Pro wired mode 0x3F is listed
/// only for completeness — dongles are what we scan for). Each dongle answers
/// for every device paired to it; today's dongles pair a single keyboard.
struct Dongle {
    pid: u16,
    tid: u8,
    /// What's typically paired to this dongle, for the display name.
    name: &'static str,
}

/// Wireless keyboard dongles known to speak this protocol. Extend this table
/// (from OpenRazer's `razerkbd_driver.h`) to cover new models.
const DONGLES: &[Dongle] = &[
    Dongle {
        pid: 0x027B,
        tid: 0x9F,
        name: "Razer Keyboard (2.4G)",
    }, // Pro Type Ultra (Wireless)
    Dongle {
        pid: 0x025C,
        tid: 0x9F,
        name: "Razer Keyboard (2.4G)",
    }, // BlackWidow V3 Pro (Wireless)
    Dongle {
        pid: 0x0290,
        tid: 0x9F,
        name: "Razer Keyboard (2.4G)",
    }, // DeathStalker V2 Pro (Wireless)
    Dongle {
        pid: 0x0296,
        tid: 0x9F,
        name: "Razer Keyboard (2.4G)",
    }, // DeathStalker V2 Pro TKL (Wireless)
    Dongle {
        pid: 0x0271,
        tid: 0x9F,
        name: "Razer Keyboard (2.4G)",
    }, // BlackWidow V3 Mini Hyperspeed (Wireless)
    Dongle {
        pid: 0x02BA,
        tid: 0x9F,
        name: "Razer Keyboard (2.4G)",
    }, // BlackWidow V4 Mini Hyperspeed (Wireless)
    Dongle {
        pid: 0x02D5,
        tid: 0x9F,
        name: "Razer Keyboard (2.4G)",
    }, // BlackWidow V4 TKL Hyperspeed (Wireless)
];

fn dongle_for(pid: u16) -> Option<&'static Dongle> {
    DONGLES.iter().find(|d| d.pid == pid)
}

// ---------------------------------------------------------------------------
// Minimal hid.dll / kernel32 FFI

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const INVALID_HANDLE_VALUE: isize = -1;

#[repr(C)]
struct HidpCaps {
    usage_page: u16,
    report_id: u8,
    _bit_position: u8,
    usage: u16,
    _usage_page2: u16,
    input_report_byte_length: u16,
    output_report_byte_length: u16,
    feature_report_byte_length: u16,
    _reserved: [u16; 17],
    _number_link_collections: u16,
    _rest: [u16; 12],
}

extern "system" {
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *mut c_void,
        disposition: u32,
        flags: u32,
        template: *mut c_void,
    ) -> isize;
    fn CloseHandle(handle: isize) -> i32;
    fn HidD_GetPreparsedData(handle: isize, preparsed: *mut isize) -> i32;
    fn HidD_FreePreparsedData(preparsed: isize) -> i32;
    fn HidP_GetCaps(preparsed: isize, caps: *mut HidpCaps) -> i32;
    fn HidD_SetFeature(handle: isize, buf: *mut u8, len: u32) -> i32;
    fn HidD_GetFeature(handle: isize, buf: *mut u8, len: u32) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// An opened dongle handle plus the profile it was matched against.
pub struct RazerDevice {
    handle: isize,
    dongle: &'static Dongle,
}

impl Drop for RazerDevice {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

impl RazerDevice {
    pub fn pid(&self) -> u16 {
        self.dongle.pid
    }

    pub fn display_name(&self) -> &'static str {
        self.dongle.name
    }
}

/// Find a supported dongle's MI_02 path via hidapi enumeration. Returns
/// `(path, profile)`. Multiple Razer dongles at once: only the first is used.
pub fn scan_dongle(api: &hidapi::HidApi) -> Option<(String, &'static Dongle)> {
    api.device_list().find_map(|info| {
        if info.vendor_id() != RAZER_VID || info.interface_number() != VENDOR_IFACE {
            return None;
        }
        let pid = info.product_id();
        dongle_for(pid).map(|dongle| (info.path().to_string_lossy().into_owned(), dongle))
    })
}

/// Open the dongle by device path with plain CreateFileW.
///
/// Access `0` (query-attributes mode) is enough: feature transfers still work
/// through a 0-access handle, while GENERIC_READ|WRITE gets ACCESS_DENIED (the
/// dongle exposes a keyboard top-level collection, so Windows locks rw opens).
pub fn open_dongle(path: &str, dongle: &'static Dongle) -> Result<RazerDevice> {
    let wpath = wide(path);
    let handle = unsafe {
        CreateFileW(
            wpath.as_ptr(),
            0,
            FILE_SHARE_READ_WRITE,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!("failed to open Razer dongle (access denied)");
    }
    Ok(RazerDevice { handle, dongle })
}

/// Build a 90-byte request payload.
fn payload(tid: u8, cmd_class: u8, cmd_id: u8, args: &[u8]) -> [u8; 90] {
    let mut r = [0u8; 90];
    r[1] = tid;
    r[5] = args.len() as u8;
    r[6] = cmd_class;
    r[7] = cmd_id;
    r[8..8 + args.len()].copy_from_slice(args);
    let crc: u8 = r[2..88].iter().fold(0u8, |acc, &b| acc ^ b);
    r[88] = crc;
    r
}

/// Send one command and return the 90-byte response payload.
fn send_recv(
    dev: &RazerDevice,
    cmd_class: u8,
    cmd_id: u8,
    args: &[u8],
    tid: u8,
) -> Result<Vec<u8>> {
    let request = payload(tid, cmd_class, cmd_id, args);
    for attempt in 0..RETRIES {
        // SET: [0x01 report id] + 90-byte payload = 91 bytes, feature transfer.
        let mut set_buf = [0u8; FEATURE_XFER];
        set_buf[0] = 0x01;
        set_buf[1..91].copy_from_slice(&request);
        let ok_set =
            unsafe { HidD_SetFeature(dev.handle, set_buf.as_mut_ptr(), FEATURE_XFER as u32) };
        if ok_set == 0 {
            if attempt + 1 < RETRIES {
                std::thread::sleep(RETRY_DELAY);
            }
            continue;
        }
        std::thread::sleep(RETRY_DELAY);

        // GET: same report id; payload comes back after the id byte.
        let mut get_buf = [0u8; FEATURE_XFER];
        get_buf[0] = 0x01;
        let ok_get =
            unsafe { HidD_GetFeature(dev.handle, get_buf.as_mut_ptr(), FEATURE_XFER as u32) };
        if ok_get == 0 {
            if attempt + 1 < RETRIES {
                std::thread::sleep(RETRY_DELAY);
            }
            continue;
        }
        // Response layout: [rid, status, tid, ...] — payload byte 0 is status.
        if get_buf[1] == STATUS_SUCCESS && get_buf[2] == tid {
            return Ok(get_buf[1..91].to_vec());
        }
        if attempt + 1 < RETRIES {
            std::thread::sleep(RETRY_DELAY);
        }
    }
    bail!(
        "no successful Razer response after {RETRIES} attempts (class 0x{cmd_class:02X} cmd 0x{cmd_id:02X})"
    )
}

/// Read battery percent (0-100) and charging flag from the dongle.
pub fn read_battery(dev: &RazerDevice) -> Result<(u8, bool)> {
    let tid = dev.dongle.tid;
    // Response payload: args start at index 8, so args[1] is payload index 9.
    // Battery level: 0-255 there.
    let resp = send_recv(dev, CMD_CLASS_BATTERY, CMD_GET_BATTERY_LEVEL, &[0, 0], tid)?;
    let raw = resp[9];
    let percent = ((u32::from(raw) * 100 + 127) / 255).min(100) as u8;

    // Charging status: args[1] = 1 when charging.
    let charging = match send_recv(
        dev,
        CMD_CLASS_BATTERY,
        CMD_GET_CHARGING_STATUS,
        &[0, 0],
        tid,
    ) {
        Ok(resp) => resp[9] != 0,
        Err(_) => false,
    };

    Ok((percent, charging))
}

/// One-shot battery state for the paired keyboard, or `None` when no supported
/// dongle is present / the keyboard is asleep (no successful round-trip).
pub fn poll_once(api: &hidapi::HidApi) -> Option<BatteryState> {
    let (path, dongle) = scan_dongle(api)?;
    let dev = open_dongle(&path, dongle).ok()?;
    let (battery_percent, is_charging) = read_battery(&dev).ok()?;
    Some(BatteryState {
        device_key: format!("{:04X}:kbd", dongle.pid),
        display_name: dongle.name.to_string(),
        pid: dongle.pid,
        device_index: 1,
        battery_percent,
        is_charging,
    })
}

/// Verify a path points at a supported dongle before opening (cheap filter).
pub fn looks_like_dongle(path: &str) -> bool {
    let pid = path
        .split("&PID_")
        .nth(1)
        .and_then(|rest| u16::from_str_radix(rest.get(..4).unwrap_or(""), 16).ok());
    match pid {
        Some(pid) => dongle_for(pid).is_some() && path.contains("MI_02"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{dongle_for, looks_like_dongle, payload, DONGLES};

    #[test]
    fn payload_layout() {
        let p = payload(0x9F, 0x07, 0x80, &[0, 0]);
        assert_eq!(p.len(), 90);
        assert_eq!(p[1], 0x9F);
        assert_eq!(p[5], 2);
        assert_eq!(p[6], 0x07);
        assert_eq!(p[7], 0x80);
        assert_eq!(&p[8..10], &[0, 0]);
        // CRC is XOR of bytes 2..=87.
        let crc: u8 = p[2..88].iter().fold(0u8, |acc, &b| acc ^ b);
        assert_eq!(p[88], crc);
        assert_eq!(p[89], 0);
    }

    #[test]
    fn known_dongles_resolve() {
        assert_eq!(dongle_for(0x027B).map(|d| d.tid), Some(0x9F));
        assert_eq!(dongle_for(0x025C).map(|d| d.tid), Some(0x9F));
        assert!(dongle_for(0x0277).is_none()); // wired keyboard, not a dongle
    }

    #[test]
    fn dongle_table_has_unique_pids() {
        let mut pids: Vec<u16> = DONGLES.iter().map(|d| d.pid).collect();
        pids.sort_unstable();
        pids.dedup();
        assert_eq!(pids.len(), DONGLES.len());
    }

    #[test]
    fn path_filter() {
        assert!(looks_like_dongle(
            r"\\?\HID#VID_1532&PID_027B&MI_02#7&13cbecd4&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}"
        ));
        assert!(looks_like_dongle(
            r"\\?\HID#VID_1532&PID_025C&MI_02#7&13cbecd4&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}"
        ));
        assert!(!looks_like_dongle(
            r"\\?\HID#VID_1532&PID_027B&MI_00#7&13cbecd4&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}"
        ));
        assert!(!looks_like_dongle(
            r"\\?\HID#VID_1532&PID_0277&MI_02#7&13cbecd4&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}"
        ));
    }
}
