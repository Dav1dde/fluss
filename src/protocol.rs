use macaddr::{MacAddr6, MacAddr8};
use nom::number::complete::{be_u128, be_u16, be_u32, be_u64, be_u8};
use nom::{call, named};
use serde::Serialize;
use serde_with::rust::display_fromstr;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Serialize)]
pub struct Record<'a> {
    pub id: u16,
    pub value: Value<'a>,
}

impl<'a> Record<'a> {
    pub fn new(id: u16, value: Value<'a>) -> Self {
        Self { id, value }
    }
}

#[derive(Debug, Serialize)]
pub struct RecordSet<'a> {
    pub id: u16,
    pub records: Vec<Record<'a>>,
}

impl<'a> RecordSet<'a> {
    pub fn new(id: u16, records: Vec<Record<'a>>) -> Self {
        Self { id, records }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Value<'a> {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bytes(&'a [u8]),
    String(String),
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    #[serde(with = "display_fromstr")]
    MacAddr6(MacAddr6),
    #[serde(with = "display_fromstr")]
    MacAddr8(MacAddr8),
    Unknown(&'a [u8]),
}

macro_rules! val_as {
    ($name:ident, $type:ident) => {
        val_as!($name, $type, $type);
    };
    ($name:ident, $type:ty, $ident:ident) => {
        pub fn $name(&self) -> Option<&$type> {
            match self {
                Self::$ident(val) => Some(val),
                _ => None,
            }
        }
    };
}

impl<'a> Value<'a> {
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            Self::U8(val) => Some(*val),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Self::U8(val) => Some(*val as u16),
            Self::U16(val) => Some(*val),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::U8(val) => Some(*val as u32),
            Self::U16(val) => Some(*val as u32),
            Self::U32(val) => Some(*val),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U8(val) => Some(*val as u64),
            Self::U16(val) => Some(*val as u64),
            Self::U32(val) => Some(*val as u64),
            Self::U64(val) => Some(*val),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match self {
            Self::Bytes(val) => Some(val),
            Self::Unknown(val) => Some(val),
            _ => None,
        }
    }

    val_as!(as_string, String);
    val_as!(as_ipv4, Ipv4Addr);
    val_as!(as_ipv6, Ipv6Addr);
    val_as!(as_mac6, MacAddr6);
    val_as!(as_mac8, MacAddr8);
}

macro_rules! val_from {
    ($type:ty, $ident:ident) => {
        impl<'a> From<$type> for Value<'a> {
            fn from(value: $type) -> Self {
                Self::$ident(value)
            }
        }
    };
}

val_from!(u8, U8);
val_from!(u16, U16);
val_from!(u32, U32);
val_from!(u64, U64);
val_from!(&'a [u8], Bytes);
val_from!(String, String);
val_from!(Ipv4Addr, Ipv4Addr);
val_from!(Ipv6Addr, Ipv6Addr);

named!(read_u8<u8>, call!(be_u8));
named!(read_u16<u16>, call!(be_u16));
named!(read_u32<u32>, call!(be_u32));
named!(read_u64<u64>, call!(be_u64));
named!(read_u128<u128>, call!(be_u128));

// TODO: parse errors and remaining data
pub fn parse_u8(input: &[u8]) -> Value {
    read_u8(input).map(|val| val.1.into()).unwrap()
}

pub fn parse_u16(input: &[u8]) -> Value {
    read_u16(input).map(|val| val.1.into()).unwrap()
}

pub fn parse_u32(input: &[u8]) -> Value {
    read_u32(input).map(|val| val.1.into()).unwrap()
}

pub fn parse_u64(input: &[u8]) -> Value {
    read_u64(input).map(|val| val.1.into()).unwrap()
}

pub fn parse_number(input: &[u8]) -> Value {
    match input.len() {
        8 => parse_u64(input),
        4 => parse_u32(input),
        2 => parse_u16(input),
        1 => parse_u8(input),
        _ => panic!("invalid byte length {} for a number", input.len()),
    }
}

pub fn parse_bytes(input: &[u8]) -> Value {
    Value::Bytes(input)
}

pub fn parse_ipv4(input: &[u8]) -> Value {
    read_u32(input)
        .map(|val| Value::Ipv4Addr(val.1.into()))
        .unwrap()
}

pub fn parse_ipv6(input: &[u8]) -> Value {
    read_u128(input)
        .map(|val| Value::Ipv6Addr(val.1.into()))
        .unwrap()
}

pub fn parse_mac6(input: &[u8]) -> Value {
    Value::MacAddr6(macaddr::MacAddr6::new(
        input[0], input[1], input[2], input[3], input[4], input[5],
    ))
}

pub fn parse_mac8(input: &[u8]) -> Value {
    Value::MacAddr8(macaddr::MacAddr8::new(
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    ))
}

pub fn parse_mac(input: &[u8]) -> Value {
    match input.len() {
        6 => parse_mac6(input),
        8 => parse_mac8(input),
        _ => panic!("invalid byte length {} for mac address", input.len()),
    }
}
