//! AMQP protocol detection module for rDpi
//!
//! 识别 0-9-1 方法/头/体/心跳帧头与 0-9-1/1.0 协议头。

mod parser;

pub use parser::{AmqpParsed, parse_amqp};
