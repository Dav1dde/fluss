use nom::number::complete::{be_u8, be_u16, be_u32, be_u64, be_u128};
use nom::{named, call, map, map_res};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct Record<'a> {
    pub id: u16,
    pub value: Value<'a>,
}

#[derive(Debug)]
pub enum Value<'a> {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bytes(&'a [u8]),
    String(String),
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    Unknown(&'a [u8]),
}

macro_rules! val_from {
    ($type:ty, $ident:ident) => {
        impl<'a> From<$type> for Value<'a> {
            fn from(value: $type) -> Self {
                Self::$ident(value)
            }
        }
    }
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
    read_u32(input).map(|val| Value::Ipv4Addr(val.1.into())).unwrap()
}

pub fn parse_ipv6(input: &[u8]) -> Value {
    read_u128(input).map(|val| Value::Ipv6Addr(val.1.into())).unwrap()
}
