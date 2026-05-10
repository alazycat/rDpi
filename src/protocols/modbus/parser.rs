//! Modbus TCP protocol parser for rDpi
//!
//! Parses Modbus TCP frames and extracts metadata.

use crate::core::types::*;

/// Parse Modbus TCP frame
pub fn parse_modbus_frame(data: &[u8]) -> Option<ModbusMetadata> {
    // MBAP Header: 7 bytes minimum
    if data.len() < 8 {
        return None;
    }

    // Transaction ID: 2 bytes
    let transaction_id = u16::from_be_bytes([data[0], data[1]]);

    // Protocol ID: must be 0x0000 for Modbus TCP
    let protocol_id = u16::from_be_bytes([data[2], data[3]]);
    if protocol_id != 0 {
        return None;
    }

    // Length: number of following bytes (unit_id + PDU)
    let length = u16::from_be_bytes([data[4], data[5]]) as usize;
    if length < 2 || data.len() < 6 + length {
        return None;
    }

    // Unit ID (Slave ID)
    let unit_id = data[6];

    // Function Code
    let function_code = data[7];

    // Check for exception response (function code with 0x80 bit set)
    let is_exception = (function_code & 0x80) != 0;

    if is_exception {
        // Exception response: function_code | 0x80 + exception_code
        if data.len() < 9 {
            return None;
        }
        let original_fc = function_code & 0x7F;
        let exception_code = data[8];

        return Some(ModbusMetadata {
            transaction_id,
            unit_id,
            function_code: original_fc,
            is_response: true,
            is_exception: true,
            exception_code: Some(exception_code),
            data: ModbusData::Exception { exception_code },
        });
    }

    // Parse based on function code
    let pdu_data = &data[8..6 + length];
    let (is_response, modbus_data) = parse_pdu(function_code, pdu_data)?;

    Some(ModbusMetadata {
        transaction_id,
        unit_id,
        function_code,
        is_response,
        is_exception: false,
        exception_code: None,
        data: modbus_data,
    })
}

/// Parse PDU based on function code
fn parse_pdu(function_code: u8, data: &[u8]) -> Option<(bool, ModbusData)> {
    match function_code {
        // Read functions - distinguish request/response by data length
        0x01 | 0x02 | 0x03 | 0x04 => {
            parse_read_function(function_code, data)
        }
        // Write single
        0x05 | 0x06 => {
            parse_write_single(function_code, data)
        }
        // Write multiple
        0x0F | 0x10 => {
            parse_write_multiple(function_code, data)
        }
        // Read/Write multiple registers
        0x17 => {
            parse_read_write_multiple(data)
        }
        // Unsupported function code
        _ => None,
    }
}

/// Parse read functions (01, 02, 03, 04)
fn parse_read_function(_function_code: u8, data: &[u8]) -> Option<(bool, ModbusData)> {
    // Request: address (2) + quantity (2) = 4 bytes
    // Response: byte_count (1) + data (N) = 1 + N bytes

    if data.len() == 4 {
        // Request
        let address = u16::from_be_bytes([data[0], data[1]]);
        let quantity = u16::from_be_bytes([data[2], data[3]]);
        Some((false, ModbusData::ReadRequest { address, quantity }))
    } else if data.len() >= 1 {
        // Response
        let byte_count = data[0] as usize;
        if data.len() < 1 + byte_count {
            return None;
        }
        let values = data[1..1 + byte_count].to_vec();
        Some((true, ModbusData::ReadResponse { byte_count: data[0], data: values }))
    } else {
        None
    }
}

/// Parse write single (05, 06)
fn parse_write_single(_function_code: u8, data: &[u8]) -> Option<(bool, ModbusData)> {
    // Both request and response: address (2) + value (2) = 4 bytes

    if data.len() != 4 {
        return None;
    }

    let address = u16::from_be_bytes([data[0], data[1]]);
    let value = data[2..4].to_vec();

    // For coil (05), value interpretation differs
    // Request: 0xFF00 = ON, 0x0000 = OFF
    // Response: echoes the request
    // We treat them the same - raw bytes

    // Heuristic: typically request comes first in a stream
    // For single write, request and response look identical
    // We'll mark as request by default (DPI can track stream state)
    Some((false, ModbusData::WriteSingleRequest { address, value }))
}

/// Parse write multiple (0F, 10)
fn parse_write_multiple(_function_code: u8, data: &[u8]) -> Option<(bool, ModbusData)> {
    // Request: address (2) + quantity (2) + byte_count (1) + values (N)
    // Response: address (2) + quantity (2)

    if data.len() < 4 {
        return None;
    }

    let address = u16::from_be_bytes([data[0], data[1]]);
    let quantity = u16::from_be_bytes([data[2], data[3]]);

    if data.len() == 4 {
        // Response
        Some((true, ModbusData::WriteMultipleResponse { address, quantity }))
    } else if data.len() >= 5 {
        // Request
        let byte_count = data[4] as usize;
        if data.len() < 5 + byte_count {
            return None;
        }
        let values = data[5..5 + byte_count].to_vec();
        Some((false, ModbusData::WriteMultipleRequest { address, quantity, values }))
    } else {
        None
    }
}

/// Parse read/write multiple registers (17)
fn parse_read_write_multiple(data: &[u8]) -> Option<(bool, ModbusData)> {
    // Request: read_addr (2) + read_qty (2) + write_addr (2) + write_qty (2) + write_byte_count (1) + write_values (N)
    // Response: byte_count (1) + read_data (N)

    if data.len() < 1 {
        return None;
    }

    // Try to distinguish: request has many fields, response starts with byte_count
    if data.len() >= 9 {
        // Likely request
        let read_addr = u16::from_be_bytes([data[0], data[1]]);
        let read_qty = u16::from_be_bytes([data[2], data[3]]);
        let write_addr = u16::from_be_bytes([data[4], data[5]]);
        let _write_qty = u16::from_be_bytes([data[6], data[7]]);
        let write_byte_count = data[8] as usize;

        if data.len() < 9 + write_byte_count {
            return None;
        }

        let write_values = data[9..9 + write_byte_count].to_vec();
        Some((false, ModbusData::ReadWriteRequest {
            read_addr,
            read_qty,
            write_addr,
            write_values,
        }))
    } else if data.len() >= 1 {
        // Likely response
        let byte_count = data[0] as usize;
        if data.len() < 1 + byte_count {
            return None;
        }
        let data_vals = data[1..1 + byte_count].to_vec();
        Some((true, ModbusData::ReadWriteResponse { byte_count: data[0], data: data_vals }))
    } else {
        None
    }
}

/// Detect Modbus TCP protocol from packet
pub fn detect_modbus(data: &[u8]) -> Option<DetectionResult> {
    let metadata = parse_modbus_frame(data)?;

    Some(
        DetectionResult::new(Protocol::Modbus)
            .with_metadata(Metadata::Modbus(metadata))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a Read Coils request (FC 01)
    fn create_read_coils_request() -> Vec<u8> {
        vec![
            0x00, 0x01,       // Transaction ID: 1
            0x00, 0x00,       // Protocol ID: 0
            0x00, 0x06,       // Length: 6 bytes following
            0x01,             // Unit ID: 1
            0x01,             // Function Code: Read Coils
            0x00, 0x01,       // Address: 1
            0x00, 0x08,       // Quantity: 8 coils
        ]
    }

    #[test]
    fn test_parse_read_coils_request() {
        let data = create_read_coils_request();
        let metadata = parse_modbus_frame(&data).unwrap();

        assert_eq!(metadata.transaction_id, 1);
        assert_eq!(metadata.unit_id, 1);
        assert_eq!(metadata.function_code, 1);
        assert!(!metadata.is_response);
        assert!(!metadata.is_exception);

        match metadata.data {
            ModbusData::ReadRequest { address, quantity } => {
                assert_eq!(address, 1);
                assert_eq!(quantity, 8);
            }
            _ => panic!("Expected ReadRequest"),
        }
    }

    #[test]
    fn test_detect_modbus() {
        let data = create_read_coils_request();
        let result = detect_modbus(&data).unwrap();

        assert_eq!(result.protocol, Protocol::Modbus);
    }

    /// Create a Read Coils response
    fn create_read_coils_response() -> Vec<u8> {
        vec![
            0x00, 0x01,       // Transaction ID: 1
            0x00, 0x00,       // Protocol ID: 0
            0x00, 0x04,       // Length: 4 bytes
            0x01,             // Unit ID: 1
            0x01,             // Function Code: Read Coils
            0x01,             // Byte Count: 1
            0x55,             // Data: 0x55 (bits: 01010101)
        ]
    }

    #[test]
    fn test_parse_read_coils_response() {
        let data = create_read_coils_response();
        let metadata = parse_modbus_frame(&data).unwrap();

        assert_eq!(metadata.transaction_id, 1);
        assert!(metadata.is_response);

        match metadata.data {
            ModbusData::ReadResponse { byte_count, data } => {
                assert_eq!(byte_count, 1);
                assert_eq!(data, vec![0x55]);
            }
            _ => panic!("Expected ReadResponse"),
        }
    }

    /// Create an exception response
    fn create_exception_response() -> Vec<u8> {
        vec![
            0x00, 0x01,       // Transaction ID: 1
            0x00, 0x00,       // Protocol ID: 0
            0x00, 0x03,       // Length: 3 bytes
            0x01,             // Unit ID: 1
            0x81,             // Function Code: 01 | 0x80 (exception)
            0x02,             // Exception Code: ILLEGAL DATA ADDRESS
        ]
    }

    #[test]
    fn test_parse_exception_response() {
        let data = create_exception_response();
        let metadata = parse_modbus_frame(&data).unwrap();

        assert!(metadata.is_response);
        assert!(metadata.is_exception);
        assert_eq!(metadata.function_code, 1); // original FC without 0x80
        assert_eq!(metadata.exception_code, Some(2));

        match metadata.data {
            ModbusData::Exception { exception_code } => {
                assert_eq!(exception_code, 2);
            }
            _ => panic!("Expected Exception"),
        }
    }

    /// Create a Write Single Coil request (FC 05)
    fn create_write_single_coil_request() -> Vec<u8> {
        vec![
            0x00, 0x02,       // Transaction ID: 2
            0x00, 0x00,       // Protocol ID: 0
            0x00, 0x06,       // Length: 6 bytes
            0x01,             // Unit ID: 1
            0x05,             // Function Code: Write Single Coil
            0x00, 0x01,       // Address: 1
            0xFF, 0x00,       // Value: ON (0xFF00)
        ]
    }

    #[test]
    fn test_parse_write_single_coil() {
        let data = create_write_single_coil_request();
        let metadata = parse_modbus_frame(&data).unwrap();

        assert_eq!(metadata.function_code, 5);

        match metadata.data {
            ModbusData::WriteSingleRequest { address, value } => {
                assert_eq!(address, 1);
                assert_eq!(value, vec![0xFF, 0x00]);
            }
            _ => panic!("Expected WriteSingleRequest"),
        }
    }

    /// Create a Write Multiple Registers request (FC 16)
    fn create_write_multiple_registers_request() -> Vec<u8> {
        vec![
            0x00, 0x03,       // Transaction ID: 3
            0x00, 0x00,       // Protocol ID: 0
            0x00, 0x0B,       // Length: 11 bytes (unit_id + PDU)
            0x01,             // Unit ID: 1
            0x10,             // Function Code: Write Multiple Registers
            0x00, 0x01,       // Address: 1
            0x00, 0x02,       // Quantity: 2 registers
            0x04,             // Byte Count: 4 bytes
            0x00, 0x01,       // Value 1
            0x00, 0x02,       // Value 2
        ]
    }

    #[test]
    fn test_parse_write_multiple_registers_request() {
        let data = create_write_multiple_registers_request();
        let metadata = parse_modbus_frame(&data).unwrap();

        assert_eq!(metadata.function_code, 16);

        match metadata.data {
            ModbusData::WriteMultipleRequest { address, quantity, values } => {
                assert_eq!(address, 1);
                assert_eq!(quantity, 2);
                assert_eq!(values, vec![0x00, 0x01, 0x00, 0x02]);
            }
            _ => panic!("Expected WriteMultipleRequest"),
        }
    }

    /// Create a Write Multiple Registers response
    fn create_write_multiple_registers_response() -> Vec<u8> {
        vec![
            0x00, 0x03,       // Transaction ID: 3
            0x00, 0x00,       // Protocol ID: 0
            0x00, 0x06,       // Length: 6 bytes
            0x01,             // Unit ID: 1
            0x10,             // Function Code: Write Multiple Registers
            0x00, 0x01,       // Address: 1
            0x00, 0x02,       // Quantity: 2
        ]
    }

    #[test]
    fn test_parse_write_multiple_registers_response() {
        let data = create_write_multiple_registers_response();
        let metadata = parse_modbus_frame(&data).unwrap();

        assert!(metadata.is_response);

        match metadata.data {
            ModbusData::WriteMultipleResponse { address, quantity } => {
                assert_eq!(address, 1);
                assert_eq!(quantity, 2);
            }
            _ => panic!("Expected WriteMultipleResponse"),
        }
    }

    #[test]
    fn test_parse_invalid_protocol_id() {
        let mut data = create_read_coils_request();
        data[3] = 0x01; // Protocol ID: 1 (invalid)
        assert!(parse_modbus_frame(&data).is_none());
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
        assert!(parse_modbus_frame(&data).is_none());
    }

    #[test]
    fn test_parse_unsupported_function_code() {
        let data = vec![
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x02,
            0x01,
            0x07,             // Function Code 7 (unsupported)
        ];
        assert!(parse_modbus_frame(&data).is_none());
    }
}