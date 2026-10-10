use std::collections::BTreeMap;

/// Сколько номеров кадров храним на одну группу (как `frameNumbers` в контракте).
pub const MAX_FRAME_NUMBERS: usize = 100;

/// Замечания к записи: ограничения реализации и дефекты данных, не выводы о протоколе.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagCode {
    UnsupportedLinkType,
    NonIp,
    Ipv6Skipped,
    NonTcp,
    IpFragment,
    TruncatedFrame,
    BadIpHeader,
    BadTcpHeader,
    BadChecksum,
    BadBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl DiagCode {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedLinkType => "unsupported_link_type",
            Self::NonIp => "non_ip",
            Self::Ipv6Skipped => "ipv6_skipped",
            Self::NonTcp => "non_tcp",
            Self::IpFragment => "ip_fragment",
            Self::TruncatedFrame => "truncated_frame",
            Self::BadIpHeader => "bad_ip_header",
            Self::BadTcpHeader => "bad_tcp_header",
            Self::BadChecksum => "bad_checksum",
            Self::BadBlock => "bad_block",
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            Self::NonIp | Self::NonTcp | Self::Ipv6Skipped | Self::UnsupportedLinkType => {
                Severity::Info
            }
            Self::IpFragment | Self::TruncatedFrame | Self::BadChecksum => Severity::Warning,
            Self::BadIpHeader | Self::BadTcpHeader | Self::BadBlock => Severity::Error,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::UnsupportedLinkType => "Канальный уровень не Ethernet",
            Self::NonIp => "Кадр не IP (ARP и др.)",
            Self::Ipv6Skipped => "IPv6 не поддерживается",
            Self::NonTcp => "Не TCP (UDP, ICMP и др.)",
            Self::IpFragment => "Фрагмент IPv4 — сборка фрагментов не поддерживается",
            Self::TruncatedFrame => "Кадр усечён при записи",
            Self::BadIpHeader => "Некорректный заголовок IPv4",
            Self::BadTcpHeader => "Некорректный заголовок TCP",
            Self::BadChecksum => "Неверная контрольная сумма",
            Self::BadBlock => "Повреждённый блок записи",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            Self::UnsupportedLinkType => {
                "Поддерживается только Ethernet; кадры других интерфейсов пропущены."
            }
            Self::NonIp => "Кадры без IPv4 пропущены: они не несут TCP-данных.",
            Self::Ipv6Skipped => "Обязательная область — IPv4; кадры IPv6 пропущены.",
            Self::NonTcp => "Кадры IPv4 с другим транспортом пропущены.",
            Self::IpFragment => {
                "Фрагменты пропущены; если в них были TCP-данные, в потоке будет дыра."
            }
            Self::TruncatedFrame => {
                "Записано меньше байтов, чем было в кадре (snaplen); недостающее — дыра в потоке."
            }
            Self::BadIpHeader => "Заголовок IPv4 не разбирается; кадр пропущен.",
            Self::BadTcpHeader => "Заголовок TCP не разбирается; кадр пропущен.",
            Self::BadChecksum => {
                "Сумма не совпала; при захвате на отправителе это часто offloading, байты учтены."
            }
            Self::BadBlock => "Запись повреждена или обрезана; разобрано то, что было до сбоя.",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiagGroup {
    pub count: u64,
    /// Первые `MAX_FRAME_NUMBERS` кадров с этим замечанием.
    pub frames: Vec<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics {
    pub groups: BTreeMap<DiagCode, DiagGroup>,
}

impl Diagnostics {
    /// `frame == 0` — замечание к файлу, а не к кадру.
    pub fn add(&mut self, code: DiagCode, frame: u32) {
        let g = self.groups.entry(code).or_default();
        g.count += 1;
        if frame > 0 && g.frames.len() < MAX_FRAME_NUMBERS {
            g.frames.push(frame);
        }
    }

    pub fn count(&self, code: DiagCode) -> u64 {
        self.groups.get(&code).map_or(0, |g| g.count)
    }

    pub fn frames(&self, code: DiagCode) -> &[u32] {
        self.groups.get(&code).map_or(&[], |g| g.frames.as_slice())
    }
}
