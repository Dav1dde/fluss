use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use serde::Serialize;
use serde_with::{serde_as, DisplayFromStr, DurationMilliSeconds};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Copy, Clone, Serialize)]
pub enum FlowType {
    IPFIX,
}

#[serde_as]
#[derive(Debug, Copy, Clone, Serialize)]
pub struct Fluss {
    pub r#type: FlowType,
    pub time_received: DateTime<Utc>,

    #[serde_as(as = "DurationMilliSeconds")]
    pub flow_age: Duration,

    pub bytes: u64,
    pub packets: u64,

    pub ethernet_type: u16,

    #[serde_as(as = "DisplayFromStr")]
    pub src_mac: MacAddr6,
    #[serde_as(as = "DisplayFromStr")]
    pub dst_mac: MacAddr6,

    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,

    pub src_net: u8,
    pub dst_net: u8,

    pub src_port: u16,
    pub dst_port: u16,

    pub vlan_id: u16,
    pub post_vlan_id: u16,

    pub post_nat_src_addr: IpAddr,
    pub post_nat_dst_addr: IpAddr,

    pub post_napt_src_port: u16,
    pub post_napt_dst_port: u16,

    pub next_hop_addr: IpAddr,
}
