mod burst;
mod fifo;

use std::{
    error::Error,
    io::BufRead,
    net::IpAddr,
    process::{Command, Stdio},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc,
    },
};

pub use burst::Burst;
use macaddr::MacAddr;
use nix::sys::signal;

pub struct CommonOptions {
    pub tshark_args: Vec<String>,
    pub inactive_time: f64,
    pub tx: Sender<Burst>,
}

pub enum CaptureType {
    IPCapture {
        opts: CommonOptions,
        ignore_ports: bool,
    },
    WLANCapture {
        opts: CommonOptions,
        no_guess: bool,
        max_deviation: u16,
    },
}

impl CaptureType {
    pub fn run(&self) -> Result<(), Box<dyn Error>> {
        let opts = match self {
            CaptureType::IPCapture { opts, .. } | CaptureType::WLANCapture { opts, .. } => opts,
        };

        let mut tshark = Command::new("tshark")
            .args(&opts.tshark_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|err| format!("Failed to start tshark: {err}"))?;

        // Set up interrupt handler (ctrl-c)
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let tshark_pid = tshark.id() as i32;
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
            let pid = nix::unistd::Pid::from_raw(tshark_pid);
            signal::kill(pid, signal::Signal::SIGINT).expect("Failed to send SIGINT to tshark");
        })?;

        let stdout = tshark.stdout.take().unwrap();
        let reader = std::io::BufReader::new(stdout);

        match self {
            CaptureType::IPCapture { ignore_ports, .. } => {
                // Spawn a thread that will handle all the burstification of the packets. Just leave parsing here
                // TODO: If too high load, we can distribute flows over threads
                let burst_tx = burst::start_ip(opts.inactive_time, *ignore_ports, opts.tx.clone())?;

                for line in reader.lines() {
                    if let Ok(packet) = IpPacket::from_tshark(&line.unwrap()) {
                        burst_tx.send(packet)?;
                    }
                }
            }
            CaptureType::WLANCapture {
                no_guess,
                max_deviation,
                ..
            } => {
                // Spawn a thread that will handle all the burstification of the packets. Just leave parsing here
                let burst_tx = burst::start_wlan(
                    opts.inactive_time,
                    *no_guess,
                    *max_deviation,
                    opts.tx.clone(),
                )?;

                for line in reader.lines() {
                    if let Ok(packet) = WlanPacket::from_tshark(&line.unwrap()) {
                        burst_tx.send(packet)?;
                    }
                }
            }
        }

        tshark.wait()?;
        Ok(())
    }
}

struct IpPacket {
    time: f64,
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    data_len: u32,
}

struct WlanPacket {
    time: f64,
    src: MacAddr,
    dst: MacAddr,
    data_len: u32,
    seq_number: u16,
}

impl IpPacket {
    fn from_tshark(line: &str) -> Result<Self, Box<dyn Error>> {
        let mut fields = line.split_whitespace();
        Ok(IpPacket {
            time: fields.next().unwrap().parse::<f64>()?,
            src: IpAddr::from_str(fields.next().unwrap())?,
            dst: IpAddr::from_str(fields.next().unwrap())?,
            src_port: fields.next().unwrap().parse::<u16>()?,
            dst_port: fields.next().unwrap().parse::<u16>()?,
            data_len: fields.next().unwrap().parse::<u32>()?,
        })
    }
}

impl WlanPacket {
    fn from_tshark(line: &str) -> Result<Self, Box<dyn Error>> {
        let mut fields = line.split_whitespace();
        Ok(WlanPacket {
            time: fields.next().unwrap().parse::<f64>()?,
            src: MacAddr::from_str(fields.next().unwrap())?,
            dst: MacAddr::from_str(fields.next().unwrap())?,
            data_len: fields.next().unwrap().parse::<u32>()?,
            seq_number: fields.next().unwrap().parse::<u16>()?,
        })
    }
}
