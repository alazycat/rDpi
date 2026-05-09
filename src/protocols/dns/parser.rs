use crate::error::{Error, Result};

#[derive(Debug, Clone)]
#[allow(dead_code)]  // Fields reserved for future use
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,           // 0=query, 1=response
    pub opcode: u8,         // 0=standard, 1=inverse, 2=status
    pub aa: bool,           // authoritative answer
    pub tc: bool,           // truncated
    pub rd: bool,           // recursion desired
    pub ra: bool,           // recursion available
    pub rcode: u8,          // response code
    pub qdcount: u16,       // question count
    pub ancount: u16,       // answer count
    pub nscount: u16,       // authority count
    pub arcount: u16,       // additional count
}

pub fn parse_header(data: &[u8]) -> Result<DnsHeader> {
    if data.len() < 12 {
        return Err(Error::TruncatedHeader);
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);

    Ok(DnsHeader {
        id,
        qr: (flags >> 15) & 1 == 1,
        opcode: ((flags >> 11) & 0xf) as u8,
        aa: (flags >> 10) & 1 == 1,
        tc: (flags >> 9) & 1 == 1,
        rd: (flags >> 8) & 1 == 1,
        ra: (flags >> 7) & 1 == 1,
        rcode: (flags & 0xf) as u8,
        qdcount,
        ancount,
        nscount,
        arcount,
    })
}

/// Parse DNS question section domain name
pub fn parse_name(data: &[u8], offset: usize) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut pos = offset;
    let mut jumped = false;
    let max_jumps = 10;
    let mut jumps = 0;

    loop {
        if pos >= data.len() {
            return Err(Error::TruncatedHeader);
        }

        let len = data[pos] as usize;

        if len == 0 {
            pos += 1;
            break;
        }

        // Check for compression pointer
        if (len & 0xc0) == 0xc0 {
            if pos + 1 >= data.len() {
                return Err(Error::TruncatedHeader);
            }
            let ptr = (((data[pos] & 0x3f) as usize) << 8) | (data[pos + 1] as usize);
            jumped = true;
            pos = ptr;
            jumps += 1;
            if jumps > max_jumps {
                return Err(Error::InvalidPacket("DNS name compression loop".into()));
            }
            continue;
        }

        pos += 1;
        if pos + len > data.len() {
            return Err(Error::TruncatedHeader);
        }

        if !name.is_empty() {
            name.push('.');
        }

        let label = std::str::from_utf8(&data[pos..pos + len])
            .map_err(|_| Error::InvalidPacket("Invalid DNS label".into()))?;
        name.push_str(label);
        pos += len;
    }

    Ok((name, if jumped { offset } else { pos }))
}
