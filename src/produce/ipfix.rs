use crate::fluss::{FlowType, Fluss};
use crate::ipfix::parser::{DataSet, FieldSpecifier};
use crate::protocol::{parse_ipv4, parse_mac, parse_number};
use macaddr::MacAddr6;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const IPFIX_BYTES_IN: u16 = 1;
const IPFIX_PACKETS_IN: u16 = 2;
const IPFIX_SRC_PORT: u16 = 7;
const IPFIX_IPV4_SRC_ADDR: u16 = 8;
const IPFIX_IPV4_SRC_MASK: u16 = 9;
const IPFIX_DST_PORT: u16 = 11;
const IPFIX_IPV4_DST_ADDR: u16 = 12;
const IPFIX_IPV4_DST_MASK: u16 = 13;
const IPFIX_IPV4_NEXT_HOP: u16 = 15;
const IPFIX_FLOW_END_SYSUPTIME: u16 = 21;
const IPFIX_FLOW_START_SYSUPTIME: u16 = 22;
const IPFIX_BYTES_OUT: u16 = 23;
const IPFIX_PACKETS_OUT: u16 = 24;
const IPFIX_MAC_SRC: u16 = 56;
const IPFIX_VLAN_ID: u16 = 58;
const IPFIX_POST_VLAN_ID: u16 = 59;
const IPFIX_MAC_DST: u16 = 81;
const IPFIX_POST_NAT_IPV4_SRC_ADDR: u16 = 225;
const IPFIX_POST_NAT_IPV4_DST_ADDR: u16 = 226;
const IPFIX_POST_NAPT_SRC_PORT: u16 = 227;
const IPFIX_POST_NAPT_DST_PORT: u16 = 228;
const IPFIX_ETHERNET_TYPE: u16 = 256;

pub struct IpfixParser {}

impl IpfixParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for IpfixParser {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> crate::ipfix::session::Parser<'a> for IpfixParser {
    type Output = Fluss;

    fn parse(&self, fields: &[FieldSpecifier], set: &DataSet<'a>) -> Option<Self::Output> {
        let mut bytes = 0;
        let mut packets = 0;
        let mut ethernet_type = 0;
        let mut src_mac = MacAddr6::broadcast();
        let mut dst_mac = MacAddr6::broadcast();
        let mut src_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut dst_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut src_net = 0;
        let mut dst_net = 0;
        let mut src_port = 0;
        let mut dst_port = 0;
        let mut vlan_id = 0;
        let mut post_vlan_id = 0;
        let mut post_nat_src_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut post_nat_dst_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut post_napt_src_port = 0;
        let mut post_napt_dst_port = 0;
        let mut next_hop_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let mut start = Duration::from_secs(0);
        let mut end = Duration::from_secs(0);

        let mut input = set.data;
        for field in fields {
            if input.len() < field.length as usize {
                tracing::trace!("early exit, no more fields, next field: {:?}", field);
                break;
            }

            // TODO better slicing, lot's of potential errors ...
            // make the parser take care of that?
            let data = &input[0..field.length as usize];
            input = &input[field.length as usize..];

            // TODO: better parsing to get rid of value wrapper
            match field.id {
                IPFIX_BYTES_IN => bytes = parse_number(data).as_u64().unwrap(),
                IPFIX_PACKETS_IN => packets = parse_number(data).as_u64().unwrap(),
                IPFIX_BYTES_OUT => bytes = parse_number(data).as_u64().unwrap(),
                IPFIX_PACKETS_OUT => packets = parse_number(data).as_u64().unwrap(),

                IPFIX_ETHERNET_TYPE => ethernet_type = parse_number(data).as_u16().unwrap(),

                IPFIX_FLOW_END_SYSUPTIME => {
                    end = Duration::from_millis(parse_number(data).as_u64().unwrap())
                }
                IPFIX_FLOW_START_SYSUPTIME => {
                    start = Duration::from_millis(parse_number(data).as_u64().unwrap())
                }

                IPFIX_MAC_SRC => src_mac = *parse_mac(data).as_mac6().unwrap(),
                IPFIX_MAC_DST => dst_mac = *parse_mac(data).as_mac6().unwrap(),

                IPFIX_IPV4_SRC_ADDR => src_addr = IpAddr::V4(*parse_ipv4(data).as_ipv4().unwrap()),
                IPFIX_IPV4_DST_ADDR => dst_addr = IpAddr::V4(*parse_ipv4(data).as_ipv4().unwrap()),

                IPFIX_IPV4_SRC_MASK => src_net = parse_number(data).as_u8().unwrap(),
                IPFIX_IPV4_DST_MASK => dst_net = parse_number(data).as_u8().unwrap(),

                IPFIX_SRC_PORT => src_port = parse_number(data).as_u16().unwrap(),
                IPFIX_DST_PORT => dst_port = parse_number(data).as_u16().unwrap(),

                IPFIX_VLAN_ID => vlan_id = parse_number(data).as_u16().unwrap(),
                IPFIX_POST_VLAN_ID => post_vlan_id = parse_number(data).as_u16().unwrap(),

                IPFIX_POST_NAT_IPV4_SRC_ADDR => {
                    post_nat_src_addr = IpAddr::V4(*parse_ipv4(data).as_ipv4().unwrap())
                }
                IPFIX_POST_NAT_IPV4_DST_ADDR => {
                    post_nat_dst_addr = IpAddr::V4(*parse_ipv4(data).as_ipv4().unwrap())
                }

                IPFIX_POST_NAPT_SRC_PORT => {
                    post_napt_src_port = parse_number(data).as_u16().unwrap()
                }
                IPFIX_POST_NAPT_DST_PORT => {
                    post_napt_dst_port = parse_number(data).as_u16().unwrap()
                }

                IPFIX_IPV4_NEXT_HOP => {
                    next_hop_addr = IpAddr::V4(*parse_ipv4(data).as_ipv4().unwrap())
                }

                _ => (),
            }
        }

        Some(Fluss {
            r#type: FlowType::IPFIX,
            time_received: chrono::offset::Utc::now(),

            flow_age: end - start,

            bytes,
            packets,

            ethernet_type,

            src_mac,
            dst_mac,

            src_addr,
            dst_addr,

            src_net,
            dst_net,

            src_port,
            dst_port,

            vlan_id,
            post_vlan_id,

            post_nat_src_addr,
            post_nat_dst_addr,

            post_napt_src_port,
            post_napt_dst_port,

            next_hop_addr,
        })
    }
}
