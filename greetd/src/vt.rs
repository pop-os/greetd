use std::error::Error;

use nix::ioctl_write_int_bad;
use nix::unistd::close;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode as StatMode;

ioctl_write_int_bad!(vt_activate, 0x5606);
ioctl_write_int_bad!(vt_waitactive, 0x5607);
ioctl_write_int_bad!(vt_kdsetmode, 0x4B3A);

pub fn activate(vt: usize) -> Result<(), Box<dyn Error>> {
    let res = open("/dev/console", OFlag::O_RDWR, StatMode::empty())?;
    unsafe {
        vt_activate(res, vt as i32)?;
        vt_waitactive(res, vt as i32)?;
    }
    close(res)?;
    Ok(())
}

#[allow(dead_code)]
pub enum Mode {
	Text,
	Graphics
}

impl Mode {
	fn to_const(&self) -> i32 {
		match self {
			Mode::Text => 0x00,
			Mode::Graphics => 0x01,
		}
	}
}

pub fn set_mode(mode: Mode) -> Result<(), Box<dyn Error>> {
    let res = open("/dev/console", OFlag::O_RDWR, StatMode::empty())?;
    let mode = mode.to_const();
    unsafe {
    	vt_kdsetmode(res, mode)?;
    }
    close(res)?;
    Ok(())
}