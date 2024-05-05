use std::{collections::HashMap, error::Error, net::IpAddr, sync::mpsc, thread, time::Duration};

use macaddr::MacAddr;

use super::{fifo::Fifo, IpPacket, WlanPacket};

pub(super) fn start_ip(
    inactive_time: f64,
    ignore_ports: bool,
    output_tx: mpsc::Sender<Burst>,
) -> Result<mpsc::Sender<IpPacket>, Box<dyn Error>> {
    let (tx, rx) = mpsc::channel::<IpPacket>();

    thread::spawn(move || {
        let mut key_time_queue = Fifo::new();
        let mut flows: HashMap<(IpAddr, IpAddr, Option<u16>, Option<u16>), IpFlow> = HashMap::new();

        let mut last_time = 0.0;
        loop {
            match rx.recv_timeout(Duration::from_secs_f64(inactive_time)) {
                Ok(packet) => {
                    last_time = packet.time;
                    create_bursts(
                        packet.time,
                        inactive_time,
                        &mut key_time_queue,
                        &mut flows,
                        &output_tx,
                    );

                    let flow_key = (
                        packet.src,
                        packet.dst,
                        (!ignore_ports).then_some(packet.src_port),
                        (!ignore_ports).then_some(packet.dst_port),
                    );

                    flows
                        .entry(flow_key)
                        .and_modify(|flow| flow.add_packet(&packet))
                        .or_insert_with(|| IpFlow::new(&packet, ignore_ports));

                    key_time_queue.enqueue((flow_key, packet.time));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // timeout, check if we should send any bursts
                    let current_time_est = last_time + inactive_time;
                    create_bursts(
                        current_time_est,
                        inactive_time,
                        &mut key_time_queue,
                        &mut flows,
                        &output_tx,
                    );
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break, // No more work coming
            }
        }
    });

    Ok(tx)
}

pub(super) fn start_wlan(
    inactive_time: f64,
    no_guess: bool,
    max_deviation: u16,
    output_tx: mpsc::Sender<Burst>,
) -> Result<mpsc::Sender<WlanPacket>, Box<dyn Error>> {
    let (tx, rx) = mpsc::channel::<WlanPacket>();

    thread::spawn(move || {
        let mut key_time_queue = Fifo::new();
        let mut flows: HashMap<(MacAddr, MacAddr), WlanFlow> = HashMap::new();

        loop {
            match rx.recv_timeout(Duration::from_secs_f64(inactive_time)) {
                Ok(packet) => {
                    create_bursts(
                        packet.time,
                        inactive_time,
                        &mut key_time_queue,
                        &mut flows,
                        &output_tx,
                    );

                    let flow_key = (packet.src, packet.dst);
                    flows
                        .entry(flow_key)
                        .and_modify(|flow| flow.add_packet(&packet))
                        .or_insert_with(|| WlanFlow::new(&packet, no_guess, max_deviation));

                    key_time_queue.enqueue((flow_key, packet.time));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // timeout, check if we should send any bursts
                    let current_time_est = 0.0 + inactive_time;
                    create_bursts(
                        current_time_est,
                        inactive_time,
                        &mut key_time_queue,
                        &mut flows,
                        &output_tx,
                    );
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break, // No more work coming
            }
        }
    });

    Ok(tx)
}

/// Inspect all flows that could have spawned a new burst for the current time
fn create_bursts<K: Clone + Eq + std::hash::Hash, F: Flow>(
    current_time: f64,
    inactive_time: f64,
    key_time_queue: &mut Fifo<(K, f64)>,
    flows: &mut HashMap<K, F>,
    output_tx: &mpsc::Sender<Burst>,
) {
    while let Some((_key, queue_time)) = key_time_queue.peek() {
        if current_time - *queue_time < inactive_time {
            // Not old enough to make is a separate burst
            break;
        }

        // Dequeue the pair
        let (key, queue_time) = key_time_queue.dequeue().unwrap();

        // Can unwrap as it ws in the fifo queue, must be in hash-map
        let flow = flows.get_mut(&key).unwrap();
        if (flow.prev_time().unwrap_or(0.0) - queue_time).abs() < 0.0001 {
            // TODO: Can we just use eq?
            // The flow has not been modified since the time was inserted into the queue
            // So it can be made a burst
            flow.send_burst(&output_tx, current_time)
                .expect("Could not send a burst!");
        }
    }
}

#[derive(Debug, Clone)]
pub struct Burst {
    pub completion_time: f64,
    pub src: String,
    pub dst: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub start: f64,
    pub end: f64,
    pub num_packets: u16,
    pub size: u32,
}

impl Burst {
    fn from_ip_packet(p: &IpPacket, ignore_ports: bool) -> Self {
        let (src_port, dst_port) = if ignore_ports {
            (None, None)
        } else {
            (Some(p.src_port), Some(p.dst_port))
        };
        Burst {
            completion_time: p.time,
            src: p.src.to_string(),
            dst: p.dst.to_string(),
            src_port,
            dst_port,
            start: p.time,
            end: p.time,
            num_packets: 1,
            size: p.data_len,
        }
    }
    fn from_wlan_packet(p: &WlanPacket) -> Self {
        Burst {
            completion_time: p.time,
            src: p.src.to_string(),
            dst: p.dst.to_string(),
            src_port: None,
            dst_port: None,
            start: p.time,
            end: p.time,
            num_packets: 1,
            size: p.data_len,
        }
    }
}

struct IpFlow {
    /// The current burst. Is None when none has started
    current_burst: Option<Burst>,

    ignore_ports: bool,
}

struct WlanFlow {
    /// The current burst. Is None when none has started
    current_burst: Option<Burst>,
    expected_seq_number: u16,
    last_packet_len: u32,
    no_guess: bool,
    max_deviation: u16,
}

impl IpFlow {
    fn new(p: &IpPacket, ignore_ports: bool) -> Self {
        IpFlow {
            ignore_ports,
            current_burst: Some(Burst::from_ip_packet(p, ignore_ports)),
        }
    }

    fn add_packet(&mut self, p: &IpPacket) {
        if let Some(ref mut burst) = &mut self.current_burst {
            burst.end = p.time;
            burst.num_packets += 1;
            burst.size += p.data_len;
        } else {
            self.current_burst = Some(Burst::from_ip_packet(p, self.ignore_ports));
        }
    }
}

impl WlanFlow {
    fn new(p: &WlanPacket, no_guess: bool, max_deviation: u16) -> Self {
        WlanFlow {
            current_burst: Some(Burst::from_wlan_packet(p)),
            expected_seq_number: p.seq_number,
            last_packet_len: p.data_len,
            no_guess,
            max_deviation,
        }
    }

    fn add_packet(&mut self, _p: &WlanPacket) {
        // Also, don't understand the if statement...
        todo!("Fixed it for IP, but Wlan might present some new difficulties with the out-of-order...");
        // if p.time - self.current_burst.end > inactive_time {
        //     self.current_burst.completion_time = p.time;
        //     tx.send(self.current_burst.clone()).unwrap();
        //     self.current_burst = Burst::from_wlan_packet(p);

        //     // Accept sequence number of packet after the inactive time.
        //     self.expected_seq_number = (p.seq_number + 1) & 4095;
        //     // Packet sequence number is what we expect.
        //     if p.seq_number == self.expected_seq_number {
        //         self.expected_seq_number = (p.seq_number + 1) & 4095;
        //         self.last_packet_len = p.data_len;
        //         self.current_burst.end = p.time;
        //         self.current_burst.num_packets += 1;
        //         self.current_burst.size += p.data_len;
        //         return;
        //     }

        //     // Packet sequence number not what we expect.
        //     let diff = (p.seq_number as i16 - self.expected_seq_number as i16) & 4095;
        //     let signed_diff = if diff <= 2048 { diff } else { diff - 4096 };

        //     // We already added this packet, but it is probably being retransmitted.
        //     // Note: not enough to filter on the retransmission bit as the first frame might be lost.
        //     if -(self.max_deviation as i16) < signed_diff && signed_diff < 0 {
        //         self.current_burst.end = p.time;
        //         return;
        //     }

        //     // The packet has a sequence number that is further along than what we expect.
        //     // Monitor mode device might have missed frames.
        //     if 0 < signed_diff && signed_diff < self.max_deviation as i16 {
        //         if !self.no_guess {
        //             // Guess the lengths of the lost frames
        //             let guess = (self.last_packet_len + p.data_len) / 2;
        //             self.current_burst.num_packets += diff as u16;
        //             self.current_burst.size += guess * diff as u32;
        //         } else {
        //             // Accept only this
        //             self.current_burst.num_packets += 1;
        //             self.current_burst.size += p.data_len;
        //         }
        //         // Bring the expected sequence number in line with the packet.
        //         self.expected_seq_number = (p.seq_number + 1) & 4095;
        //         self.last_packet_len = p.data_len;
        //         self.current_burst.end = p.time;
        //     } else {
        //         // In case of a larger deviation, might be a single outlier, go to next expected.
        //         self.expected_seq_number = (self.expected_seq_number + 1) & 4095;
        //     }
        // }
    }
}

trait Flow {
    /// Gets the last time a packet was added to the flow
    fn prev_time(&self) -> Option<f64>;

    /// Sends the current burst to outupt, and reset it
    fn send_burst(
        &mut self,
        output_tx: &mpsc::Sender<Burst>,
        time: f64,
    ) -> Result<(), Box<dyn Error>>;
}

impl Flow for IpFlow {
    fn prev_time(&self) -> Option<f64> {
        self.current_burst.as_ref().map(|burst| burst.end)
    }

    fn send_burst(
        &mut self,
        output_tx: &mpsc::Sender<Burst>,
        current_time: f64,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(mut burst) = std::mem::replace(&mut self.current_burst, None) {
            burst.completion_time = current_time;
            output_tx.send(burst)?;
            Ok(())
        } else {
            Err(Box::from(
                "Internal error: Tried to transmit an empty burst",
            ))
        }
    }
}

impl Flow for WlanFlow {
    fn prev_time(&self) -> Option<f64> {
        self.current_burst.as_ref().map(|burst| burst.end)
    }

    fn send_burst(
        &mut self,
        output_tx: &mpsc::Sender<Burst>,
        current_time: f64,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(mut burst) = std::mem::replace(&mut self.current_burst, None) {
            burst.completion_time = current_time;
            output_tx.send(burst)?;
            Ok(())
        } else {
            Err(Box::from(
                "Internal error: Tried to transmit an empty burst",
            ))
        }
    }
}
