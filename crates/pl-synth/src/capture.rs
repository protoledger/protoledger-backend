use crate::rng::Rng;

pub const LINKTYPE_ETHERNET: u16 = 1;
pub const DEFAULT_SNAPLEN: u32 = 65535;
/// 2026-10-01T00:00:00Z: время захвата не зависит от момента генерации.
pub const BASE_TS_US: u64 = 1_790_812_800_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Pcapng,
    Pcap,
}

impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Format::Pcapng => "pcapng",
            Format::Pcap => "pcap",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub ts_us: u64,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

/// Запись в памяти: кадры в порядке захвата, время растёт монотонно.
#[derive(Clone, Debug)]
pub struct Capture {
    pub snaplen: u32,
    pub frames: Vec<Frame>,
    clock_us: u64,
    jitter: Rng,
}

impl Capture {
    pub fn new(snaplen: u32, seed: u64) -> Self {
        Self {
            snaplen,
            frames: Vec::new(),
            clock_us: BASE_TS_US,
            jitter: Rng::new(seed ^ 0x7473_6A69_7474_6572),
        }
    }

    /// Добавляет кадр, усекая его до snaplen. Возвращает номер кадра (с 1, как в Wireshark).
    pub fn push(&mut self, mut data: Vec<u8>) -> u32 {
        self.clock_us += self.jitter.range(80, 2500);
        let orig_len = data.len() as u32;
        data.truncate(self.snaplen as usize);
        self.frames.push(Frame {
            ts_us: self.clock_us,
            orig_len,
            data,
        });
        self.frames.len() as u32
    }

    /// Пауза в захвате (между сеансами, перед повтором и т.п.).
    pub fn idle(&mut self, us: u64) {
        self.clock_us += us;
    }

    pub fn encode(&self, format: Format) -> Vec<u8> {
        match format {
            Format::Pcapng => self.to_pcapng(),
            Format::Pcap => self.to_pcap(),
        }
    }

    /// Классический pcap, little-endian, микросекунды.
    pub fn to_pcap(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.snaplen.to_le_bytes());
        out.extend_from_slice(&u32::from(LINKTYPE_ETHERNET).to_le_bytes());
        for f in &self.frames {
            out.extend_from_slice(&((f.ts_us / 1_000_000) as u32).to_le_bytes());
            out.extend_from_slice(&((f.ts_us % 1_000_000) as u32).to_le_bytes());
            out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&f.orig_len.to_le_bytes());
            out.extend_from_slice(&f.data);
        }
        out
    }

    /// pcapng: SHB, один IDB (Ethernet, микросекунды по умолчанию), EPB на каждый кадр.
    pub fn to_pcapng(&self) -> Vec<u8> {
        let mut out = Vec::new();

        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        block(&mut out, 0x0A0D_0D0A, &shb);

        let mut idb = Vec::new();
        idb.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&self.snaplen.to_le_bytes());
        block(&mut out, 0x0000_0001, &idb);

        for f in &self.frames {
            let mut epb = Vec::with_capacity(20 + f.data.len() + 3);
            epb.extend_from_slice(&0u32.to_le_bytes());
            epb.extend_from_slice(&((f.ts_us >> 32) as u32).to_le_bytes());
            epb.extend_from_slice(&(f.ts_us as u32).to_le_bytes());
            epb.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
            epb.extend_from_slice(&f.orig_len.to_le_bytes());
            epb.extend_from_slice(&f.data);
            epb.resize(epb.len().next_multiple_of(4), 0);
            block(&mut out, 0x0000_0006, &epb);
        }
        out
    }
}

fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    let total = (12 + body.len()) as u32;
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
}
