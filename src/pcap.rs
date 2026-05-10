//! PCAP file processing module for rDpi
//!
//! Provides batch processing of pcap/pcapng files.
//!
//! # Feature
//!
//! This module is only available when the `pcap` feature is enabled.
//!
//! # Example
//!
//! ```rust,ignore
//! use rdpi::Detector;
//! use rdpi::pcap::PcapProcessor;
//!
//! let detector = Detector::new();
//! let processor = PcapProcessor::new(detector);
//!
//! for result in processor.process_file("capture.pcap")? {
//!     println!("{:?}", result);
//! }
//! ```

#[cfg(feature = "pcap")]
use crate::{Detector, DetectionResult, Error};
#[cfg(feature = "pcap")]
use pcap_file::pcap::PcapReader;
#[cfg(feature = "pcap")]
use pcap_file::pcapng::PcapNgReader;
#[cfg(feature = "pcap")]
use std::fs::File;
#[cfg(feature = "pcap")]
use std::io::BufReader;
#[cfg(feature = "pcap")]
use std::path::Path;

/// PCAP 文件处理迭代器
///
/// 读取 pcap 或 pcapng 文件，逐包返回检测结果。
#[cfg(feature = "pcap")]
pub struct PcapIterator {
    reader: PcapReaderType,
    detector: Detector,
}

#[cfg(feature = "pcap")]
enum PcapReaderType {
    Legacy(PcapReader<BufReader<File>>),
    Ng(PcapNgReader<BufReader<File>>),
}

#[cfg(feature = "pcap")]
impl PcapIterator {
    fn new_legacy(path: &Path, detector: Detector) -> crate::error::Result<Self> {
        let file = File::open(path)
            .map_err(|e| Error::Parse(format!("Failed to open pcap file: {}", e)))?;
        let buf_reader = BufReader::new(file);

        let reader = PcapReader::new(buf_reader)
            .map_err(|e| Error::Parse(format!("Failed to parse pcap: {}", e)))?;

        Ok(Self {
            reader: PcapReaderType::Legacy(reader),
            detector,
        })
    }

    fn new_ng(path: &Path, detector: Detector) -> crate::error::Result<Self> {
        let file = File::open(path)
            .map_err(|e| Error::Parse(format!("Failed to open pcapng file: {}", e)))?;
        let buf_reader = BufReader::new(file);

        let reader = PcapNgReader::new(buf_reader)
            .map_err(|e| Error::Parse(format!("Failed to parse pcapng: {}", e)))?;

        Ok(Self {
            reader: PcapReaderType::Ng(reader),
            detector,
        })
    }

    /// 获取底层 Detector 的引用
    pub fn detector(&self) -> &Detector {
        &self.detector
    }

    /// 获取底层 Detector 的可变引用
    pub fn detector_mut(&mut self) -> &mut Detector {
        &mut self.detector
    }
}

#[cfg(feature = "pcap")]
impl Iterator for PcapIterator {
    type Item = crate::error::Result<Option<(u64, DetectionResult)>>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.reader {
            PcapReaderType::Legacy(reader) => {
                match reader.next_packet() {
                    Some(Ok(packet)) => {
                        let ts = packet.timestamp.as_nanos() / 1000; // 转换为微秒
                        match self.detector.detect(&packet.data) {
                            Ok(Some(result)) => Some(Ok(Some((ts as u64, result)))),
                            Ok(None) => Some(Ok(None)),
                            Err(e) => Some(Err(e)),
                        }
                    }
                    Some(Err(e)) => Some(Err(Error::Parse(format!("Failed to read packet: {}", e)))),
                    None => None, // 文件结束
                }
            }
            PcapReaderType::Ng(reader) => {
                match reader.next_block() {
                    Some(Ok(block)) => {
                        use pcap_file::pcapng::Block;
                        match block {
                            Block::EnhancedPacket(epb) => {
                                let ts = epb.timestamp.as_nanos() / 1000; // 转换为微秒
                                match self.detector.detect(&epb.data) {
                                    Ok(Some(result)) => Some(Ok(Some((ts as u64, result)))),
                                    Ok(None) => Some(Ok(None)),
                                    Err(e) => Some(Err(e)),
                                }
                            }
                            Block::SimplePacket(spb) => {
                                match self.detector.detect(&spb.data) {
                                    Ok(Some(result)) => Some(Ok(Some((0, result)))),
                                    Ok(None) => Some(Ok(None)),
                                    Err(e) => Some(Err(e)),
                                }
                            }
                            _ => {
                                // 跳过非数据包块，继续读取下一个
                                self.next()
                            }
                        }
                    }
                    Some(Err(e)) => Some(Err(Error::Parse(format!("Failed to read block: {}", e)))),
                    None => None, // 文件结束
                }
            }
        }
    }
}

/// PCAP 处理器
///
/// 提供便捷的 pcap 文件处理接口。
#[cfg(feature = "pcap")]
pub struct PcapProcessor {
    detector: Detector,
}

#[cfg(feature = "pcap")]
impl PcapProcessor {
    /// 创建新的处理器
    pub fn new() -> Self {
        Self {
            detector: Detector::new(),
        }
    }

    /// 使用自定义 Detector 创建处理器
    pub fn with_detector(detector: Detector) -> Self {
        Self { detector }
    }

    /// 处理 pcap 文件，返回迭代器
    pub fn process_file<P: AsRef<Path>>(self, path: P) -> crate::error::Result<PcapIterator> {
        let path = path.as_ref();

        // 根据文件扩展名选择格式
        if path.extension().map_or(false, |ext| ext == "pcapng") {
            PcapIterator::new_ng(path, self.detector)
        } else {
            PcapIterator::new_legacy(path, self.detector)
        }
    }
}

#[cfg(feature = "pcap")]
impl Default for PcapProcessor {
    fn default() -> Self {
        Self::new()
    }
}