use super::parser::{DataSet, FieldSpecifier, Packet, TemplateRecord};
use crate::protocol::{
    parse_ipv4, parse_ipv6, parse_mac, parse_number, parse_string, Record, RecordSet, Value,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::iter::Iterator;

pub trait Parser<'a> {
    type Output;

    fn parse(&self, fields: &[FieldSpecifier], set: &DataSet<'a>) -> Option<Self::Output>;
}

pub struct Session<P> {
    templates: RwLock<HashMap<u16, Vec<FieldSpecifier>>>,
    // parsers: HashMap<u16, Parser>,
    parser: P,
}

impl<P> Session<P> {
    pub fn new(parser: P) -> Self {
        Self {
            templates: RwLock::new(HashMap::new()),
            parser,
        }
    }

    pub fn get_parser(&self) -> &P {
        &self.parser
    }
}

impl<'a, P> Session<P>
where
    P: Parser<'a>,
{
    pub fn parse(&'a self, packet: &'a Packet) -> impl Iterator<Item = <P as Parser<'a>>::Output> {
        // let's assume for now template records always come first,
        // if not, all we miss is a few records

        use super::parser::Set::*;
        packet
            .sets
            .iter()
            .filter_map(move |set| match set {
                TemplateSet(records) => {
                    self.add_records(records);
                    None
                }
                DataSet(data) => Some(self.parse_data_set(data).into_iter()),
                _ => None,
            })
            .flatten()
    }

    fn add_records(&self, records: &[TemplateRecord]) {
        let mut templates = self.templates.write();
        for record in records {
            tracing::trace!("template: {}, fields: {:?}", record.id, record.fields);
            templates.insert(record.id, record.fields.clone());
        }
    }

    fn parse_data_set(&'a self, set: &DataSet<'a>) -> Vec<P::Output> {
        let templates = self.templates.read();
        let fields = match templates.get(&set.id) {
            Some(v) => v,
            None => return vec![],
        };

        let length = fields.iter().map(|f| f.length as usize).sum::<usize>();
        // TODO: maybe can get rid of this collect, either by getting the lock in the iter,
        // cloning the fields or some zip() magic
        // TODO: make sure the set is divisble by `length`, otherwise error
        set.data
            .chunks(length)
            .filter_map(move |data| self.parser.parse(&fields, &DataSet { id: set.id, data }))
            .collect()
    }
}

pub type FieldExtractor = fn(&[u8]) -> Value;
struct NameFn(String, FieldExtractor);

pub struct DebugParser<T> {
    parsers: HashMap<u16, NameFn>,
    delegate: T,
}

impl<T> DebugParser<T> {
    pub fn new(parser: T) -> Self {
        Self {
            parsers: get_default_field_parsers(),
            delegate: parser,
        }
    }

    pub fn set_parser(
        &mut self,
        id: u16,
        name: impl Into<String>,
        extractor: FieldExtractor,
    ) -> &mut Self {
        self.parsers.insert(id, NameFn(name.into(), extractor));
        self
    }
}

impl<'a, T> Parser<'a> for DebugParser<T>
where
    T: Parser<'a>,
{
    type Output = T::Output;

    fn parse(&self, fields: &[FieldSpecifier], set: &DataSet<'a>) -> Option<Self::Output> {
        for (field, data) in set.with_fields(fields) {
            match self.parsers.get(&field.id) {
                Some(NameFn(name, parser)) => {
                    tracing::info!("{}:{} = {:?}", field.id, name, parser(data))
                }
                None => tracing::info!("{}:<???> = {:?}", field.id, data),
            }
        }

        self.delegate.parse(fields, set)
    }
}

pub struct FieldParser {
    parsers: HashMap<u16, NameFn>,
}

impl FieldParser {
    pub fn builder() -> FieldParserBuilder {
        FieldParserBuilder::new()
    }
}

impl<'a> Parser<'a> for FieldParser {
    type Output = RecordSet<'a>;

    fn parse(&self, fields: &[FieldSpecifier], set: &DataSet<'a>) -> Option<Self::Output> {
        let mut result = Vec::new();
        let mut input = set.data;

        // TODO figure out lifetimes for set.with_fields()
        for field in fields {
            let rs = field.read(input).unwrap();
            input = rs.0;
            let data = rs.1;

            if let Some(NameFn(name, parser)) = self.parsers.get(&field.id) {
                tracing::trace!(parser = name.as_str(), "pre parse: {:?} {:?}", field, data);
                let value = parser(data);
                tracing::trace!(
                    parser = name.as_str(),
                    "post: parse: {:?} {:?}",
                    field,
                    value
                );

                result.push(Record::new(field.id, value));
            } else {
                tracing::trace!("no parser registered for field: {:?}", field);
                result.push(Record::new(field.id, Value::Unknown(data)));
            }
        }

        Some(RecordSet::new(set.id, result))
    }
}

pub struct FieldParserBuilder {
    parsers: HashMap<u16, NameFn>,
}

impl FieldParserBuilder {
    fn new() -> Self {
        Self {
            parsers: HashMap::new(),
        }
    }

    pub fn with_default_fields(mut self) -> Self {
        self.parsers.extend(get_default_field_parsers());
        self
    }

    pub fn with_field(mut self, id: u16, name: impl Into<String>, fe: FieldExtractor) -> Self {
        self.parsers.insert(id, NameFn(name.into(), fe));
        self
    }

    pub fn build(self) -> FieldParser {
        FieldParser {
            parsers: self.parsers,
        }
    }
}

macro_rules! map {
    ($($key:expr => ($name:expr, $parser:expr)),+) => {
        let mut m = HashMap::new();
        $(m.insert($key, NameFn($name.to_string(), $parser));)+
        m
    }
}

fn get_default_field_parsers() -> HashMap<u16, NameFn> {
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
        56 => ("sourceMacAddress", parse_mac),
        57 => ("postDestinationMacAddress", parse_mac),
        58 => ("vlanId", parse_number),
        59 => ("postVlanId", parse_number),
        60 => ("ipVersion", parse_number),
        61 => ("flowDirection", parse_number),
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
        80 => ("destinationMacAddress", parse_mac),
        81 => ("postSourceMacAddress", parse_mac),
        82 => ("interfaceName", parse_string),
        83 => ("interfaceDescription", parse_string),
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
        218 => ("tcpSynTotalCount", parse_number),
        219 => ("tcpFinTotalCount", parse_number),
        220 => ("tcpRstTotalCount", parse_number),
        221 => ("tcpPshTotalCount", parse_number),
        222 => ("tcpAckTotalCount", parse_number),
        222 => ("tcpAckTotalCount", parse_number),
        223 => ("tcpUrgTotalCount", parse_number),
        225 => ("postNATSourceIPv4Address", parse_ipv4),
        226 => ("postNATDestinationIPv4Address", parse_ipv4),
        227 => ("postNAPTSourceTransportPort", parse_number),
        228 => ("postNAPTDestinationTransportPort", parse_number),
        233 => ("firewallEvent", parse_number),
        240 => ("ethernetHeaderLength", parse_number),
        243 => ("dot1qVlanId", parse_number),
        244 => ("dot1qPriority", parse_number),
        256 => ("ethernetType", parse_number),
        352 => ("layer2OctetDeltaCount", parse_number),
        353 => ("layer2OctetTotalCount", parse_number),
        354 => ("ingressUnicastPacketTotalCount", parse_number),
        355 => ("ingressMulticastPacketTotalCount", parse_number),
        356 => ("ingressBroadcastPacketTotalCount", parse_number),
        357 => ("egressUnicastPacketTotalCount", parse_number),
        358 => ("egressBroadcastPacketTotalCount", parse_number),
        359 => ("monitoringIntervalStartMilliSeconds", parse_number),
        360 => ("monitoringIntervalEndMilliSeconds", parse_number),
        368 => ("ingressInterfaceType", parse_number),
        369 => ("egressInterfaceType", parse_number)
    }
}
