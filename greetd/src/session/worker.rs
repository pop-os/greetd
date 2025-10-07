use std::{
    env,
    ffi::{c_char, CString},
    os::unix::net::UnixDatagram,
};

use nix::{
    sys::wait::waitpid,
    unistd::{execve, fork, initgroups, setgid, setsid, setuid, ForkResult},
};
use pam_sys::{PamFlag, PamItemType};
use serde::{Deserialize, Serialize};

use super::{
    conv::SessionConv,
    prctl::{prctl, PrctlOption},
};
use crate::{error::Error, pam::session::PamSession, terminal};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthMessageType {
    Visible,
    Secret,
    Info,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TerminalMode {
    Terminal {
        path: String,
        vt: usize,
        switch: bool,
    },
    Stdin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SessionClass {
    Greeter,
    User,
}

impl SessionClass {
    fn as_str(&self) -> &str {
        match self {
            SessionClass::Greeter => "greeter",
            SessionClass::User => "user",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ParentToSessionChild<'a> {
    InitiateLogin {
        service: &'a str,
        class: SessionClass,
        user: &'a str,
        authenticate: bool,
        tty: TerminalMode,
        source_profile: bool,
        listener_path: &'a str,
    },
    PamResponse {
        resp: Option<String>,
    },
    Args {
        env: Vec<String>,
        cmd: Vec<String>,
    },
    Start,
    Cancel,
}

impl<'a> ParentToSessionChild<'a> {
    pub fn recv(
        sock: &UnixDatagram,
        data: &'a mut [u8; 10240],
    ) -> Result<ParentToSessionChild<'a>, Error> {
        let len = sock.recv(&mut data[..])?;
        let msg = serde_json::from_slice(&data[..len])?;
        Ok(msg)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SessionChildToParent {
    Success,
    Error(Error),
    PamMessage { style: AuthMessageType, msg: String },
    FinalChildPid(u64),
}

impl SessionChildToParent {
    pub fn send(&self, sock: &UnixDatagram) -> Result<(), Error> {
        let out = serde_json::to_vec(self)?;
        sock.send(&out)?;
        Ok(())
    }
}

/// The entry point for the session worker process. The session worker is
/// responsible for the entirety of the session setup and execution. It is
/// started by Session::start.
fn worker(sock: &UnixDatagram) -> Result<(), Error> {
    let mut data = [0; 10240];
    let (service, class, user, authenticate, tty, source_profile, listener_path) =
        match ParentToSessionChild::recv(sock, &mut data)? {
            ParentToSessionChild::InitiateLogin {
                service,
                class,
                user,
                authenticate,
                tty,
                source_profile,
                listener_path,
            } => (
                service,
                class,
                user,
                authenticate,
                tty,
                source_profile,
                listener_path,
            ),
            ParentToSessionChild::Cancel => return Err("cancelled".into()),
            msg => return Err(format!("expected InitiateLogin or Cancel, got: {:?}", msg).into()),
        };

    let conv = Box::pin(SessionConv::new(sock));
    let mut pam = PamSession::start(service, user, conv)?;

    if authenticate {
        pam.authenticate(PamFlag::NONE)?;
    }
    pam.acct_mgmt(PamFlag::NONE)?;

    // Not the credentials you think.
    pam.setcred(PamFlag::ESTABLISH_CRED)?;

    // Mark authentication as a success.
    SessionChildToParent::Success.send(sock)?;

    // Add GREETD_SOCK if this is a greeter session - we do this early as we are about to reuse the
    // buffer, invalidating our borrow.
    if let SessionClass::Greeter = class {
        pam.putenv(&format!("GREETD_SOCK={}", &listener_path))?;
    }

    // Fetch our arguments from the parent.
    let (env, cmd) = match ParentToSessionChild::recv(sock, &mut data)? {
        ParentToSessionChild::Args { env, cmd } => (env, cmd),
        ParentToSessionChild::Cancel => return Err("cancelled".into()),
        msg => return Err(format!("expected Args or Cancel, got: {:?}", msg).into()),
    };

    SessionChildToParent::Success.send(sock)?;

    // Await start request from our parent.
    match ParentToSessionChild::recv(sock, &mut data)? {
        ParentToSessionChild::Start => (),
        ParentToSessionChild::Cancel => return Err("cancelled".into()),
        msg => return Err(format!("expected Start or Cancel, got: {:?}", msg).into()),
    };

    let pam_username = pam.get_user()?;

    let user = nix::unistd::User::from_name(&pam_username)?.ok_or("unable to get user info")?;

    // Make this process a session leader.
    setsid().map_err(|e| format!("unable to become session leader: {}", e))?;

    match &tty {
        TerminalMode::Stdin => (),
        TerminalMode::Terminal { path, vt, switch } => {
            // Tell PAM what TTY we're targetting, which is used by logind.
            pam.set_item(PamItemType::TTY, &format!("tty{}", vt))?;
            pam.putenv(&format!("XDG_VTNR={}", vt))?;

            // Opening our target terminal.
            let target_term = terminal::Terminal::open(path)?;

            // Set the target VT mode to text for compatibility. Other login managers
            // set this to graphics, but that disallows start of textual applications,
            // which greetd aims to support.
            target_term.kd_setmode(terminal::KdMode::Text)?;

            // Clear TTY so that it will be empty when we switch to it.
            target_term.term_clear()?;

            // A bit more work if a VT switch is required.
            if *switch && *vt != target_term.vt_get_current()? {
                // Perform a switch to the target VT, simultaneously resetting it to
                // VT_AUTO.
                target_term.vt_setactivate(*vt)?;
            }

            // Connect std(in|out|err), and make this our controlling TTY.
            target_term.term_connect_pipes()?;
            target_term.term_take_ctty()?;
        }
    }

    // PAM has to be provided a bunch of environment variables before
    // open_session. We pass any environment variables from our greeter
    // through here as well. This allows them to affect PAM (more
    // specifically, pam_systemd.so), as well as make it easier to gather
    // and set all environment variables later.
    let prepared_env = [
        "XDG_SEAT=seat0".to_string(),
        format!("XDG_SESSION_CLASS={}", class.as_str()),
        format!("USER={}", user.name),
        format!("LOGNAME={}", user.name),
        format!("HOME={}", user.dir.to_string_lossy()),
        format!("SHELL={}", user.shell.to_string_lossy()),
        format!(
            "TERM={}",
            env::var("TERM").unwrap_or_else(|_| "linux".to_string())
        ),
    ];
    for e in env.iter().chain(prepared_env.iter()) {
        pam.putenv(e)?;
    }

    // Session time!
    pam.open_session(PamFlag::NONE)?;

    // We are done with PAM, clear variables that the child will not need.
    _ = pam.putenv("XDG_SESSION_CLASS");

    // Prepare some strings in C format that we'll need.
    let cusername = CString::new(&*user.name)?;
    let command = if source_profile {
        format!(
            "[ -f /etc/profile ] && . /etc/profile; [ -f $HOME/.profile ] && . $HOME/.profile; exec {}",
            cmd.join(" ")
        )
    } else {
        format!("exec {}", cmd.join(" "))
    };

    // Extract PAM environment for use with execve below.
    let pamenvlist = pam.getenvlist()?;
    let envvec = pamenvlist.to_vec();

    // PAM is weird and gets upset if you exec from the process that opened
    // the session, registering it automatically as a log-out. Thus, we must
    // exec in a new child.
    let child = match unsafe { fork() }.map_err(|e| format!("unable to fork: {}", e))? {
        ForkResult::Parent { child, .. } => child,
        ForkResult::Child => {
            // It is important that we do *not* return from here by
            // accidentally using '?'. The process *must* exit from within
            // this match arm.

            // Drop privileges to target user
            initgroups(&cusername, user.gid).expect("unable to init groups");
            setgid(user.gid).expect("unable to set GID");
            setuid(user.uid).expect("unable to set UID");

            // Set our parent death signal. setuid/setgid above resets the
            // death signal, which is why we do this here.
            prctl(PrctlOption::SET_PDEATHSIG(libc::SIGTERM)).expect("unable to set death signal");

            // Change working directory
            if let Err(e) = env::set_current_dir(user.dir) {
                eprintln!("unable to set working directory: {}", e);
            }

            // Run
            let cpath = CString::new("/bin/sh").unwrap();
            execve(
                &cpath,
                &[
                    &cpath,
                    &CString::new("-c").unwrap(),
                    &CString::new(command).unwrap(),
                ],
                &envvec,
            )
            .expect("unable to exec");

            unreachable!("after exec");
        }
    };

    // Update utmp to store an entry for the new session.
    let _utmp_session = UtmpSession::new(user, child, tty, class)
        .inspect_err(|e| eprintln!("{e}"))
        .ok();

    // Signal the inner PID to the parent process.
    SessionChildToParent::FinalChildPid(child.as_raw() as u64).send(sock)?;
    sock.shutdown(std::net::Shutdown::Both)?;

    // Set our parent death signal. setsid above resets the signal, hence our
    // late assignment, which is why we do this here.
    prctl(PrctlOption::SET_PDEATHSIG(libc::SIGTERM))?;

    // Wait for process to terminate, handling EINTR as necessary.
    loop {
        match waitpid(child, None) {
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                eprintln!("session: waitpid on inner child failed: {}", e);
                break;
            }
            Ok(_) => break,
        }
    }

    // Close the session. This step requires root privileges to run, as it
    // will result in various forms of login teardown (including unmounting
    // home folders, telling logind that the session ended, etc.). This is
    // why we cannot drop privileges in this process, but must do it in the
    // inner-most child.
    pam.close_session(PamFlag::NONE)?;
    pam.setcred(PamFlag::DELETE_CRED)?;
    pam.end()?;

    Ok(())
}

/// [`libc::utmpx`] session line for a logged in user.
///
/// `utmp` is a record of logged in sessions. It's read by programs such as `who` or `w` to list
/// users who are logged in as well as the TTY for their session.
///
/// Writing to `utmp` requires elevated permissions though any program may read from it. Therefore,
/// it is set and unset by greetd rather than deferring it to greeters.
///
/// # Sources
/// The code to set and unset the `utmp` line is based on lightdm, lemurs, and the C examples from
/// the utmpx.h man pages.
struct UtmpSession {
    session: libc::utmpx,
}

impl UtmpSession {
    /// Add a utmp entry for a newly logged in user.
    fn new(
        user: nix::unistd::User,
        child: nix::unistd::Pid,
        tty: TerminalMode,
        session_class: SessionClass,
    ) -> Result<Self, Error> {
        let TerminalMode::Terminal { path, vt, .. } = tty else {
            return Err(Error::Io(format!(
                "Error writing user {} ({}) to utmp file: Not a terminal",
                user.name, user.uid
            )));
        };
        if !matches!(session_class, SessionClass::User) {
            return Err(Error::Error(format!(
                "Error writing user {} ({}) to utmp file: Not user session",
                user.name, user.uid
            )));
        }

        // Largely based off of lightdm, lemurs, and utmpx/utmp.h man pages
        // SAFETY: Types need neither to be specially constructed nor specially dropped
        let mut session: libc::utmpx = unsafe { std::mem::zeroed() };

        session.ut_type = libc::USER_PROCESS;
        // User session PID
        session.ut_pid = child.as_raw();
        // Copy username
        // SAFETY:
        // * ut_user and name are valid pointers
        // * ut_user is at least __UT_NAMESIZE bytes
        // * ut_user is nul terminated due to being zeroed, and if the user name is __UT_NAMESIZE
        // bytes then it does not need to end in a nul according to the manual
        // * The username from Nix is ASCII according to the docs
        unsafe {
            libc::strncpy(
                session.ut_user.as_mut_ptr(),
                user.name.as_ptr().cast(),
                libc::__UT_NAMESIZE,
            );
        }

        // TTY. More or less verbatim from lemurs with a bug fix.
        let ut_id = if vt > 9 {
            b'S' as c_char
        } else {
            (b'0' + vt as u8) as c_char
        };
        session.ut_id[0] = 't' as c_char;
        session.ut_id[1] = 't' as c_char;
        session.ut_id[2] = 'y' as c_char;
        session.ut_id[3] = ut_id;

        // TTY path
        // SAFETY: Same as the username code except with __UT_LINESIZE as the size
        let ut_line = path.strip_prefix("/dev/").unwrap_or(path.as_str());
        unsafe {
            libc::strncpy(
                session.ut_line.as_mut_ptr(),
                ut_line.as_ptr().cast(),
                libc::__UT_LINESIZE,
            );
        }

        // Hostname
        // SAFETY: gethostname is safe to call. It will write up to __UT_HOSTSIZE
        // bytes of the host name, truncating if necessary.
        unsafe {
            // Some implementations leave this unset or set it to other variables like DISPLAY.
            libc::gethostname(session.ut_host.as_mut_ptr(), libc::__UT_HOSTSIZE);
        }

        // Time
        let mut timeval = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        // SAFETY: Safe to call and doesn't define errors
        unsafe {
            libc::gettimeofday(&raw mut timeval, std::ptr::null_mut());
        }
        // utmpx's internal struct timeval is different from the real timeval due to backwards
        // compatibility with 32 bit programs.
        // The 64-bit, corrected timeval can be opted into with defines but libc doesn't have a way
        // to do so yet.
        // LightDM (C) doesn't have this issue but lemurs (Rust) does. I also checked SDDM and GDM.
        session.ut_tv.tv_sec = timeval.tv_sec as i32;
        session.ut_tv.tv_usec = timeval.tv_usec as i32;

        // SAFETY:
        // * Rewinding the internal utmp file pos is safe and should be done per the manual.
        // * utmpx contains valid data from the launched session and is non-null.
        let error = unsafe {
            libc::setutxent();
            libc::pututxline(&session)
                .is_null()
                .then(nix::errno::Errno::last)
        };

        // SAFETY:
        // * Closing the utmp file handle is recommended by the man pages and doesn't have invariants
        // to uphold
        unsafe {
            libc::endutxent();
        }

        if let Some(error) = error {
            Err(Error::Io(format!(
                "Error writing user {} ({}) to utmp file: {}",
                user.name, user.uid, error
            )))
        } else {
            Ok(Self { session })
        }
    }
}

impl Drop for UtmpSession {
    fn drop(&mut self) {
        // The man page notes that init cleans up utmp entries automatically when the process
        // exits. Both lightdm and lemurs clean up the utmp line manually so we will too.

        let ut_pid = self.session.ut_pid;
        // Zero out the struct. This is less finicky than doing it by hand.
        self.session = unsafe { std::mem::zeroed() };

        // Restore PID and set the indicator that line should be removed.
        self.session.ut_pid = ut_pid;
        self.session.ut_type = libc::DEAD_PROCESS;

        // SAFETY:
        // * Same as [`UtmpSession::new`]
        // * The utmp API will safely update the line
        unsafe {
            libc::setutxent();
            libc::pututxline(&self.session);
            libc::endutxent();
        }
    }
}

pub fn main(sock: &UnixDatagram) -> Result<(), Error> {
    if let Err(e) = worker(sock) {
        SessionChildToParent::Error(e.clone()).send(sock)?;
        Err(e)
    } else {
        Ok(())
    }
}
