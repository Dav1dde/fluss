use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32};
use nom::IResult;
use nom::{call, complete, cond, do_parse, length_count, many1, named, peek, switch, take};

#[derive(Debug)]
pub struct Packet<'a> {
    pub version: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
    pub sets: Vec<Set<'a>>,
}

#[derive(Debug)]
pub struct DataSet<'a> {
    pub id: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct TemplateRecord {
    pub id: u16,
    pub fields: Vec<FieldSpecifier>,
}

#[derive(Debug)]
pub enum Set<'a> {
    DataSet(DataSet<'a>),
    TemplateSet(Vec<TemplateRecord>),
}

#[derive(Debug, Copy, Clone)]
pub struct FieldSpecifier {
    pub id: u16,
    pub length: u16,
    pub enterprise_id: Option<u32>,
}

named!(
    parse_field_specifier<FieldSpecifier>,
    do_parse!(
        id: be_u16
            >> length: be_u16
            >> enterprise_id: cond!(id > 0x8000, be_u32)
            >> (FieldSpecifier {
                id: id & 0x7fff,
                length,
                enterprise_id
            })
    )
);

named!(
    do_parse_template_set<Vec<TemplateRecord>>,
    many1!(do_parse!(
        id: be_u16
            >> fields: length_count!(be_u16, parse_field_specifier)
            >> (TemplateRecord { id, fields })
    ))
);

pub fn parse_template_set(input: &[u8]) -> IResult<&[u8], Set> {
    let (input, _) = be_u16(input)?; // set id
    let (input, length) = be_u16(input)?;

    let (input, data) = take(length - 4)(input)?;
    let (r, sets) = do_parse_template_set(data)?;
    assert_eq!(r.len(), 0); // TODO: return a proper error here

    Ok((input, Set::TemplateSet(sets)))
}

named!(
    parse_data_set<Set>,
    do_parse!(
        id: be_u16
            >> length: be_u16
            >> data: take!(length - 4)
            >> (Set::DataSet(DataSet { id, data }))
    )
);

named!(
    parse_set<Set>,
    switch!(
        peek!(be_u16),
        2 => call!(parse_template_set) |
        _ => call!(parse_data_set)
    )
);

fn do_parse(input: &[u8]) -> IResult<&[u8], Packet> {
    let (input, version) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (remaining, input) = take(length - 4)(input)?; // already read 4 bytes
    let (input, export_time) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, observation_domain_id) = be_u32(input)?;

    let (_input, sets) = many1!(input, complete!(parse_set))?;
    assert_eq!(_input.len(), 0); // TODO: return a proper error here
    assert_eq!(remaining.len(), 0); // TODO: return a proper error here

    Ok((
        remaining,
        Packet {
            version,
            export_time,
            sequence_number,
            observation_domain_id,
            sets,
        },
    ))
}

// TODO better error
pub fn parse(input: &[u8]) -> anyhow::Result<Packet> {
    match do_parse(input) {
        Ok((_, packet)) => Ok(packet),
        Err(err) => Err(anyhow::anyhow!("parsing error: {:?}", err)),
    }
}
