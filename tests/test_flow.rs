use rdpi::core::flow::*;
use rdpi::core::types::*;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn make_key() -> FlowKey {
    FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 12345,
        dst_port: 53,
        transport: TransportProto::Udp,
    }
}

#[test]
fn test_flow_table_create() {
    let table = FlowTable::new(100, Duration::from_secs(60));
    assert_eq!(table.len(), 0);
}

#[test]
fn test_flow_table_get_or_create() {
    let mut table = FlowTable::new(100, Duration::from_secs(60));
    let key = make_key();

    {
        let flow = table.get_or_create(key.clone());
        assert_eq!(flow.key, key);
    }
    assert_eq!(table.len(), 1);
}

#[test]
fn test_flow_table_get_existing() {
    let mut table = FlowTable::new(100, Duration::from_secs(60));
    let key = make_key();

    table.get_or_create(key.clone());
    table.get_or_create(key.clone());

    assert_eq!(table.len(), 1);
}
