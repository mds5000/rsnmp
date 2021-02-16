use std::io;
use bytes::BufMut;
use std::net::Ipv4Addr; 
use bcder::{Oid, Ia5String, OctetString, Tag, Mode};
use bcder::encode;
use bcder::encode::{PrimitiveContent, Primitive, Constructed};

enum Version {
    V1,
    V2C,
    V3,
}

impl Version {
    fn as_int(self) -> i32 {
        match self {
            V1 => 0,
            V2C => 1,
            V3 => 2
        }
    }
}

/* Definitions from RFC 2578 */
const TAG_IPADDR: u32 = 0;
const TAG_COUNTER32: u32 = 1;
const TAG_GAUGE32: u32 = 2;
const TAG_TIMETICKS: u32 = 3;
const TAG_OPAQUE: u32 = 4;
/* The definitions skip Application 5 for some reason */
const TAG_COUNTER64: u32 = 6;

const TAG_MSG_GET: u32 = 0x20;
const TAG_MSG_GETNEXT: u32 = 0x21;
const TAG_MSG_RESPONSE: u32 = 0x22;
const TAG_MSG_SET: u32 = 0x23;
const TAG_MSG_TRAPV1: u32 = 0x24;
const TAG_MSG_GETBULK: u32 = 0x25;
const TAG_MSG_INFORM: u32 = 0x26;
const TAG_MSG_TRAPV2: u32 = 0x27;
const TAG_MSG_REPORT: u32 = 0x28;

#[derive(Clone)]
struct TimeTicks(u32);
impl TimeTicks {
    fn as_primitive(&self) -> Primitive<u32> {
        self.0.encode_as(Tag::application(TAG_TIMETICKS))
   }
}


#[derive(Clone)]
enum Value {
    Null,
    Identifier(Oid),
    Integer(i32),
    IpAddress(Ipv4Addr),
    Gauge32(u32),
    Counter32(u32),
    Counter64(u64),
    Timeticks(TimeTicks),
    OctetStr(Vec<u8>),
    Opaque(Vec<u8>),
    //noSuchObject
    //noSuchInstance
    //EndOfMIBView
}

fn ip_to_bytes(addr: &Ipv4Addr) -> [u8;4] {
    u32::from_ne_bytes(addr.octets()).to_be_bytes()
}

impl encode::Values for Value {
    fn encoded_len(&self, mode: Mode) -> usize {
        match self {
            Value::Null => ().encode().encoded_len(mode),
            Value::Identifier(v) => v.encode().encoded_len(mode),
            Value::Integer(v) => v.encode().encoded_len(mode),
            Value::IpAddress(addr) => ip_to_bytes(addr).encode_as(Tag::application(TAG_IPADDR)).encoded_len(mode),
            Value::Gauge32(v) => v.encode_as(Tag::application(TAG_GAUGE32)).encoded_len(mode),
            Value::Counter32(v) => v.encode_as(Tag::application(TAG_COUNTER32)).encoded_len(mode),
            Value::Counter64(v) => v.encode_as(Tag::application(TAG_COUNTER64)).encoded_len(mode),
            Value::Timeticks(v) => v.as_primitive().encoded_len(mode),
            Value::OctetStr(v) => v.encode().encoded_len(mode),
            Value::Opaque(v) => v.encode_as(Tag::application(TAG_OPAQUE)).encoded_len(mode)
        }
    }

    fn write_encoded<W: io::Write>(&self, mode: Mode, target: &mut W) -> Result<(), io::Error> {
        match self {
            Value::Null => ().encode().write_encoded(mode, target),
            Value::Identifier(v) => v.encode().write_encoded(mode, target),
            Value::Integer(v) => v.encode().write_encoded(mode, target),
            Value::IpAddress(addr) => ip_to_bytes(addr).encode_as(Tag::application(TAG_IPADDR)).write_encoded(mode, target),
            Value::Gauge32(v) => v.encode_as(Tag::application(TAG_GAUGE32)).write_encoded(mode, target),
            Value::Counter32(v) => v.encode_as(Tag::application(TAG_COUNTER32)).write_encoded(mode, target),
            Value::Counter64(v) => v.encode_as(Tag::application(TAG_COUNTER64)).write_encoded(mode, target),
            Value::Timeticks(v) => v.as_primitive().write_encoded(mode, target),
            Value::OctetStr(v) => v.encode().write_encoded(mode, target),
            Value::Opaque(v) => v.encode_as(Tag::application(TAG_OPAQUE)).write_encoded(mode, target),
        }
    }
}


struct Message {
    version: Version,
    community: String,
    data: Pdu,
}

impl Message {
    fn encode(self) -> impl encode::Values {
        let community = Ia5String::from_string(self.community).expect("Community string can contain only ASCII char set.");
        encode::sequence((self.version.as_int().encode(), community.encode(), self.data.encode()))
    }
}

enum PduTag {
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    Trap, //V1
    GetBulkRequest, //BULK
    InformRequest,
    TrapV2, //V2
    Report
}

impl PduTag {
    fn as_tag(self) -> Tag {
        match self {
            GetRequest => Tag::ctx(TAG_MSG_GET),
            GetNextRequest => Tag::ctx(TAG_MSG_GETNEXT),
            GetResponse => Tag::ctx(TAG_MSG_RESPONSE),
            SetRequest => Tag::ctx(TAG_MSG_SET),
            Trap => Tag::ctx(TAG_MSG_TRAPV1),
            GetBulkRequest => Tag::ctx(TAG_MSG_GETBULK),
            InformRequest => Tag::ctx(TAG_MSG_INFORM),
            TrapV2 => Tag::ctx(TAG_MSG_TRAPV2),
            Report => Tag::ctx(TAG_MSG_REPORT),
        }

    }
}

struct Pdu {
    tag: PduTag,
    request_id: i32,
    err_status: i32,
    err_index: i32,
    bindings: Vec<VarBinding>,
}

impl Pdu {
    fn encode(self) -> impl encode::Values {
        encode::sequence_as(self.tag.as_tag(), (
            self.request_id.encode(),
            self.err_status.encode(),
            self.err_index.encode(),
            encode::sequence(encode::iter(self.bindings.into_iter().map(|v| v.encode())))
        ))
    }
}

struct TrapV1 {
    enterprise: Oid,
    agent_address: Ipv4Addr,
    generic_trap: i32,
    specific_trap: i32,
    time_stamp: TimeTicks,
    bindings: Vec<VarBinding>,
}

#[derive(Clone)]
struct VarBinding {
    name: Oid,
    value: Value
}

impl VarBinding {
    fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.name.encode(),
            self.value
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcder::oid::ConstOid;
    use bcder::encode::Values;

    fn assert_val(w: bytes::buf::Writer<std::vec::Vec<u8>>, val: &[u8]) {
        let buf = w.into_inner();
        assert_eq!(buf, val);
    }

    #[test]
    fn encode_values() {
        // Null
        let mut buf = vec!{}.writer();
        let v = Value::Null;
        let r = v.write_encoded(Mode::Ber, &mut buf);
        assert!(r.is_ok());
        assert_val(buf, &[5,0]);

        // OID
        let mut buf = vec!{}.writer();
        let oid: ConstOid = ConstOid{&[1,3,6,1,2,1]};
        let v = Value::Identifier(oid)
        let r = v.write_encoded(Mode::Ber, &mut buf);
        assert!(r.is_ok());
        assert_val(buf, &[2,1,5]);

        // Integer
        let mut buf = vec!{}.writer();
        let v = Value::Integer(5);
        let r = v.write_encoded(Mode::Ber, &mut buf);
        assert!(r.is_ok());
        assert_val(buf, &[2,1,5]);

        // Ip Address
        let mut buf = vec!{}.writer();
        let v = Value::IpAddress(Ipv4Addr::new(10, 0, 0, 1));
        let r = v.write_encoded(Mode::Ber, &mut buf);
        assert!(r.is_ok());
        assert_val(buf, &[64,4,1,0,0,10]);

    }
}