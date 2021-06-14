use crate::data::{parse_ipv4, parse_ipv6, parse_number, Value, parse_bytes};
use crate::{DataSet, FieldSpecifier, Packet, Set as SSet, TemplateRecord};
use std::collections::HashMap;
use std::iter::Iterator;

pub struct FieldParser {
    name: String,
    func: fn(&[u8]) -> Value,
}

impl FieldParser {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn parse<'a>(&self, value: &'a [u8]) -> Value<'a> {
        (self.func)(value)
    }
}

#[derive(Debug)]
pub struct Field<'a>(pub u16, pub Value<'a>);
#[derive(Debug)]
pub struct Set<'a>(pub u16, pub Vec<Field<'a>>);

pub struct Builder {
    field_parser: Option<HashMap<u16, FieldParser>>,
}

impl Builder {
    fn new() -> Self {
        Self { field_parser: None }
    }

    pub fn with_default_parser(mut self) -> Self {
        self.field_parser = Some(get_default_parsers());
        self
    }

    pub fn build(mut self) -> Session {
        Session {
            templates: HashMap::new(),
            field_parser: self.field_parser.take().unwrap_or_else(|| HashMap::new()),
        }
    }
}

pub struct Session {
    templates: HashMap<u16, Vec<FieldSpecifier>>,
    field_parser: HashMap<u16, FieldParser>,
}

impl Session {
    pub fn new() -> Self {
        Self::builder().with_default_parser().build()
    }

    pub fn builder() -> Builder {
        Builder::new()
    }

    pub fn get_field_name(&self, field: &Field) -> Option<&str> {
        self.get_field_name_u16(field.0)
    }

    pub fn get_field_name_u16(&self, id: u16) -> Option<&str> {
        self.field_parser.get(&id).map(|parser| parser.name())
    }

    pub fn feed<'a>(&mut self, packet: &'a Packet) -> Vec<Set<'a>> {
        // let's assume for now template records always come first,
        // should probably check the spec

        packet
            .sets
            .iter()
            .filter_map(|set| match set {
                SSet::TemplateSet(records) => {
                    self.add_records(records);
                    None
                }
                SSet::DataSet(data) => Some(self.parse(data)),
            })
            .collect::<Vec<_>>()
    }

    fn add_records(&mut self, records: &Vec<TemplateRecord>) {
        for record in records {
            self.templates.insert(record.id, record.fields.clone());
        }
    }

    fn parse<'a>(&mut self, set: &DataSet<'a>) -> Set<'a> {
        let fields = match self.templates.get(&set.id) {
            Some(a) => a,
            None => {
                tracing::debug!("no record for set id {}", set.id);
                // TODO should probably be a Set::Unparsed and a Set::Parsed or something
                return Set(set.id, vec![Field(0, Value::Unknown(set.data))]);
            }
        };

        let mut result = Vec::new();

        let mut input = set.data;
        for field in fields {
            // TODO better slicing, lot's of potential errors ...
            let data = &input[0..field.length as usize];
            input = &input[field.length as usize..];

            let parser = self.field_parser.get(&field.id).expect(&format!("unknown parser {}", field.id));
            tracing::trace!(parser = parser.name(), "pre parse: {:?} {:?}", field, data);
            let value = parser.parse(data);
            tracing::trace!(
                parser = parser.name(),
                "post: parse: {:?} {:?}",
                field,
                value
            );

            result.push(Field(field.id, value));
        }

        Set(set.id, result)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! map {
    ($($key:expr => ($name:expr, $parser:expr)),+) => {
        let mut m = HashMap::new();
        $(m.insert($key, FieldParser { name: $name.to_string(), func: $parser });)+
        m
    }
}

// default field_parsers for enterprise number 0
pub fn get_default_parsers() -> HashMap<u16, FieldParser> {
    map! {
        1 => ("octetDeltaCount", parse_number),
        2 => ("packetDeltaCount", parse_number),
        4 => ("protocolIdentifier", parse_number),
        5 => ("classOfServiceIPv4", parse_number),
        6 => ("tcpControlBits", parse_number),
        7 => ("sourceTransportPort", parse_number),
        8 => ("sourceIPv4Address", parse_ipv4),
        9 => ("sourceIPv4Mask", parse_number),
        10 => ("ingressInterface", parse_number),
        11 => ("destinationTransportPort", parse_number),
        12 => ("destinationIPv4Address", parse_ipv4),
        13 => ("destinationIPv4Mask", parse_number),
        14 => ("egressInterface", parse_number),
        15 => ("ipNextHopIPv4Address", parse_ipv4),
        16 => ("bgpSourceAsNumber", parse_number),
        17 => ("bgpDestinationAsNumber", parse_number),
        18 => ("bgpNextHopIPv4Address", parse_number),
        19 => ("postMCastPacketDeltaCount", parse_number),
        20 => ("postMCastOctetDeltaCount", parse_number),
        21 => ("flowEndSysUpTime", parse_number),
        22 => ("flowStartSysUpTime", parse_number),
        23 => ("postOctetDeltaCount", parse_number),
        24 => ("postPacketDeltaCount", parse_number),
        25 => ("minimumPacketLength", parse_number),
        26 => ("maximumPacketLength", parse_number),
        27 => ("sourceIPv6Address", parse_ipv6),
        28 => ("destinationIPv6Address", parse_ipv6),
        29 => ("sourceIPv6Mask", parse_number),
        30 => ("destinationIPv6Mask", parse_number),
        31 => ("flowLabelIPv6", parse_number),
        32 => ("icmpTypeCodeIPv4", parse_number),
        33 => ("igmpType", parse_number),
        36 => ("flowActiveTimeOut", parse_number),
        37 => ("flowInactiveTimeout", parse_number),
        40 => ("exportedOctetTotalCount", parse_number),
        41 => ("exportedMessageTotalCount", parse_number),
        42 => ("exportedFlowTotalCount", parse_number),
        44 => ("sourceIPv4Prefix", parse_number),
        45 => ("destinationIPv4Prefix", parse_number),
        46 => ("mplsTopLabelType", parse_number),
        47 => ("mplsTopLabelIPv4Address", parse_ipv4),
        52 => ("minimumTtl", parse_number),
        53 => ("maximumTtl", parse_number),
        54 => ("identificationIPv4", parse_number),
        55 => ("postClassOfServiceIPv4", parse_number),
        56 => ("sourceMacAddress", parse_bytes),
        57 => ("postDestinationMacAddress", parse_bytes),
        58 => ("vlanId", parse_number),
        59 => ("postVlanId", parse_number),
        60 => ("ipVersion", parse_number),
        62 => ("ipNextHopIPv6Address", parse_ipv6),
        63 => ("bgpNextHopIPv6Address", parse_ipv6),
        64 => ("ipv6ExtensionHeaders", parse_number),
        // 70 => ("mplsTopLabelStackEntry", mpls_stack),
        // 71 => ("mplsLabelStackEntry2", mpls_stack),
        // 72 => ("mplsLabelStackEntry3", mpls_stack),
        // 73 => ("mplsLabelStackEntry4", mpls_stack),
        // 74 => ("mplsLabelStackEntry5", mpls_stack),
        // 75 => ("mplsLabelStackEntry6", mpls_stack),
        // 76 => ("mplsLabelStackEntry7", mpls_stack),
        // 77 => ("mplsLabelStackEntry8", mpls_stack),
        // 78 => ("mplsLabelStackEntry9", mpls_stack),
        // 79 => ("mplsLabelStackEntry10", mpls_stack),
        80 => ("destinationMacAddress", parse_bytes),
        81 => ("postSourceMacAddress", parse_bytes),
        82 => ("interfaceName", parse_number),
        83 => ("interfaceDescription", parse_number),
        84 => ("samplerName", parse_number),
        85 => ("octetTotalCount", parse_number),
        86 => ("packetTotalCount", parse_number),
        88 => ("fragmentOffsetIPv4", parse_number),
        128 => ("bgpNextAdjacentAsNumber", parse_number),
        129 => ("bgpPrevAdjacentAsNumber", parse_number),
        130 => ("exporterIPv4Address", parse_ipv4),
        131 => ("exporterIPv6Address", parse_ipv6),
        132 => ("droppedOctetDeltaCount", parse_number),
        133 => ("droppedPacketDeltaCount", parse_number),
        134 => ("droppedOctetTotalCount", parse_number),
        135 => ("droppedPacketTotalCount", parse_number),
        136 => ("flowEndReason", parse_number),
        137 => ("classOfServiceIPv6", parse_number),
        138 => ("postClassOfServiceIPv6", parse_number),
        139 => ("icmpTypeCodeIPv6", parse_number),
        140 => ("mplsTopLabelIPv6Address", parse_ipv6),
        141 => ("lineCardId", parse_number),
        142 => ("portId", parse_number),
        143 => ("meteringProcessId", parse_number),
        144 => ("exportingProcessId", parse_number),
        145 => ("templateId", parse_number),
        146 => ("wlanChannelId", parse_number),
        147 => ("wlanSsid", parse_number),
        148 => ("flowId", parse_number),
        149 => ("sourceId", parse_number),
        150 => ("flowStartSeconds", parse_number),
        151 => ("flowEndSeconds", parse_number),
        152 => ("flowStartMilliSeconds", parse_number),
        153 => ("flowEndMilliSeconds", parse_number),
        154 => ("flowStartMicroSeconds", parse_number),
        155 => ("flowEndMicroSeconds", parse_number),
        156 => ("flowStartNanoSeconds", parse_number),
        157 => ("flowEndNanoSeconds", parse_number),
        158 => ("flowStartDeltaMicroSeconds", parse_number),
        159 => ("flowEndDeltaMicroSeconds", parse_number),
        160 => ("systemInitTimeMilliSeconds", parse_number),
        161 => ("flowDurationMilliSeconds", parse_number),
        162 => ("flowDurationMicroSeconds", parse_number),
        163 => ("observedFlowTotalCount", parse_number),
        164 => ("ignoredPacketTotalCount", parse_number),
        165 => ("ignoredOctetTotalCount", parse_number),
        166 => ("notSentFlowTotalCount", parse_number),
        167 => ("notSentPacketTotalCount", parse_number),
        168 => ("notSentOctetTotalCount", parse_number),
        169 => ("destinationIPv6Prefix", parse_number),
        170 => ("sourceIPv6Prefix", parse_number),
        171 => ("postOctetTotalCount", parse_number),
        172 => ("postPacketTotalCount", parse_number),
        173 => ("flowKeyIndicator", parse_number),
        174 => ("postMCastPacketTotalCount", parse_number),
        175 => ("postMCastOctetTotalCount", parse_number),
        176 => ("icmpTypeIPv4", parse_number),
        177 => ("icmpCodeIPv4", parse_number),
        178 => ("icmpTypeIPv6", parse_number),
        179 => ("icmpCodeIPv6", parse_number),
        180 => ("udpSourcePort", parse_number),
        181 => ("udpDestinationPort", parse_number),
        182 => ("tcpSourcePort", parse_number),
        183 => ("tcpDestinationPort", parse_number),
        184 => ("tcpSequenceNumber", parse_number),
        185 => ("tcpAcknowledgementNumber", parse_number),
        186 => ("tcpWindowSize", parse_number),
        187 => ("tcpUrgentPointer", parse_number),
        188 => ("tcpHeaderLength", parse_number),
        189 => ("ipHeaderLength", parse_number),
        190 => ("totalLengthIPv4", parse_number),
        191 => ("payloadLengthIPv6", parse_number),
        192 => ("ipTimeToLive", parse_number),
        193 => ("nextHeaderIPv6", parse_number),
        194 => ("ipClassOfService", parse_number),
        195 => ("ipDiffServCodePoint", parse_number),
        196 => ("ipPrecedence", parse_number),
        197 => ("fragmentFlagsIPv4", parse_number),
        198 => ("octetDeltaSumOfSquares", parse_number),
        199 => ("octetTotalSumOfSquares", parse_number),
        200 => ("mplsTopLabelTtl", parse_number),
        201 => ("mplsLabelStackLength", parse_number),
        202 => ("mplsLabelStackDepth", parse_number),
        203 => ("mplsTopLabelExp", parse_number),
        204 => ("ipPayloadLength", parse_number),
        205 => ("udpMessageLength", parse_number),
        206 => ("isMulticast", parse_number),
        207 => ("internetHeaderLengthIPv4", parse_number),
        208 => ("ipv4Options", parse_number),
        209 => ("tcpOptions", parse_number),
        210 => ("paddingOctets", parse_number),
        213 => ("headerLengthIPv4", parse_number),
        214 => ("mplsPayloadLength", parse_number),
        224 => ("ipTotalLength", parse_number),
        225 => ("postNATSourceIPv4Address", parse_ipv4),
        226 => ("postNATDestinationIPv4Address", parse_ipv4),
        227 => ("postNAPTSourceTransportPort", parse_number),
        228 => ("postNAPTDestinationTransportPort", parse_number)
    }
}
