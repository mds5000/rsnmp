use rasn::de::Error;
use rasn::types::{Class, Implicit, Utf8String};
pub use rasn::types::{ObjectIdentifier, OctetString};
use rasn::{AsnType, Decode, Decoder, Encode, Encoder, Tag};
use std::fmt;
use std::time;
use std::net::Ipv4Addr;

/* Definitions from RFC 2578 */
const TAG_IPADDR: Tag = Tag::new(Class::Application, 0);
const TAG_COUNTER32: Tag = Tag::new(Class::Application, 1);
const TAG_GAUGE32: Tag = Tag::new(Class::Application, 2);
const TAG_TIMETICKS: Tag = Tag::new(Class::Application, 3);
const TAG_OPAQUE: Tag = Tag::new(Class::Application, 4);
const TAG_COUNTER64: Tag = Tag::new(Class::Application, 6);
const TAG_NOSUCHOBJECT: Tag = Tag::new(Class::Context, 0);
const TAG_NOSUCHINSTANCE: Tag = Tag::new(Class::Context, 1);
const TAG_ENDOFMIBVIEW: Tag = Tag::new(Class::Context, 2);

struct ObjectIdentifierDisplayWrapper<'a>(&'a ObjectIdentifier);
impl<'a> fmt::Display for ObjectIdentifierDisplayWrapper<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subids = self.0;
        for subid in &subids[0..subids.len() - 1] {
            write!(f, "{}.", subid)?;
        }
        write!(f, "{}", subids[subids.len() - 1])
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct TimeTicks(u32);

impl TimeTicks {
    fn new(ticks: u32) -> TimeTicks {
        TimeTicks { 0: ticks }
    }
}

impl AsnType for TimeTicks {
    const TAG: Tag = TAG_TIMETICKS;
}

impl Encode for TimeTicks {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        self.0.encode_with_tag(encoder, tag)
    }
}

impl Decode for TimeTicks {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {

        let ticks = u32::decode_with_tag(decoder, tag)?;
        Ok(Self(ticks))
    }
}

impl From<time::Duration> for TimeTicks {
    fn from(d: time::Duration) -> TimeTicks {
        TimeTicks{ 0: (d.as_millis() / 10) as u32 }
    }
}

impl fmt::Display for TimeTicks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ticks = self.0;
        let hundredths = ticks % 100;
        ticks /= 100;
        let secs = ticks % 60;
        ticks /= 60;
        let minutes = ticks % 60;
        ticks /= 60;
        let hours = ticks % 24;
        let days = ticks / 24;

        write!(f, "({}) {}d {}:{:02}:{:02}.{:02}", self.0, days, hours, minutes, secs, hundredths)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Value {
    Null,
    Oid(ObjectIdentifier),
    Integer(i32),
    IpAddr(Ipv4Addr),
    Gauge32(u32),
    Counter32(u32),
    Counter64(u64),
    Timeticks(TimeTicks),
    OctetStr(OctetString),
    Opaque(OctetString),
    NoSuchObject,
    NoSuchInstance,
    EndOfMIBView,
}

fn ip_to_bytes(addr: &Ipv4Addr) -> OctetString {
    OctetString::copy_from_slice(&u32::from_ne_bytes(addr.octets()).to_be_bytes())
}

fn bytes_to_ip(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

impl AsnType for Value {
    const TAG: Tag = TAG_NOSUCHOBJECT;
}

impl Encode for Value {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
        match self {
            Value::Null => ().encode(encoder),
            Value::Oid(v) => v.encode(encoder),
            Value::Integer(v) => v.encode(encoder),
            Value::IpAddr(addr) => ip_to_bytes(addr).encode_with_tag(encoder, TAG_IPADDR),
            Value::Gauge32(v) => v.encode_with_tag(encoder, TAG_GAUGE32),
            Value::Counter32(v) => v.encode_with_tag(encoder, TAG_COUNTER32),
            Value::Counter64(v) => v.encode_with_tag(encoder, TAG_COUNTER64),
            Value::Timeticks(v) => v.encode(encoder),
            Value::OctetStr(v) => v.encode(encoder),
            Value::Opaque(v) => v.encode_with_tag(encoder, TAG_OPAQUE),
            Value::NoSuchObject => ().encode_with_tag(encoder, TAG_NOSUCHOBJECT),
            Value::NoSuchInstance => ().encode_with_tag(encoder, TAG_NOSUCHINSTANCE),
            Value::EndOfMIBView => ().encode_with_tag(encoder, TAG_ENDOFMIBVIEW),
        }
    }
}

impl Decode for Value {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        let tag = decoder.peek_tag()?;
        let value = match tag {
            Tag::NULL => <()>::decode(decoder).map(|_| Value::Null)?,
            Tag::OBJECT_IDENTIFIER => Value::Oid(ObjectIdentifier::decode(decoder)?),
            Tag::INTEGER => Value::Integer(i32::decode(decoder)?),
            TAG_IPADDR => {
                let bytes = decoder.decode_octet_string(TAG_IPADDR)?;
                if bytes.len() != 4 {
                    return Err(D::Error::custom(format!(
                        "Expected 4 bytes, received {}",
                        bytes.len()
                    )));
                }
                Value::IpAddr(bytes_to_ip(&bytes))
            }
            TAG_GAUGE32 => Value::Gauge32(u32::decode_with_tag(decoder, TAG_GAUGE32)?),
            TAG_COUNTER32 => Value::Counter32(u32::decode_with_tag(decoder, TAG_COUNTER32)?),
            TAG_COUNTER64 => Value::Counter64(u64::decode_with_tag(decoder, TAG_COUNTER64)?),
            TAG_TIMETICKS => Value::Timeticks(TimeTicks::decode(decoder)?),
            Tag::OCTET_STRING => Value::OctetStr(OctetString::decode(decoder)?),
            TAG_OPAQUE => Value::Opaque(OctetString::decode_with_tag(decoder, TAG_OPAQUE)?),
            TAG_NOSUCHOBJECT => {
                <()>::decode_with_tag(decoder, TAG_NOSUCHOBJECT).map(|_| Value::Null)?
            }
            TAG_NOSUCHINSTANCE => {
                <()>::decode_with_tag(decoder, TAG_NOSUCHINSTANCE).map(|_| Value::Null)?
            }
            TAG_ENDOFMIBVIEW => {
                <()>::decode_with_tag(decoder, TAG_ENDOFMIBVIEW).map(|_| Value::Null)?
            }
            _ => {
                return Err(D::Error::custom(format!(
                    "Unexpected tag {:?}, expected Value",
                    tag
                )))
            }
        };

        Ok(value)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => write!(f, "<null>"),
            Value::Oid(v) => write!(f, "{}", ObjectIdentifierDisplayWrapper(v)),
            Value::Integer(v) => write!(f, "{}", v),
            Value::IpAddr(v) => write!(f, "{}", v),
            Value::Gauge32(v) => write!(f, "{}", v),
            Value::Counter32(v) => write!(f, "{}", v),
            Value::Counter64(v) => write!(f, "{}", v),
            Value::Timeticks(v) => write!(f, "{}", v),
            Value::OctetStr(v) => write!(f, "{}", std::str::from_utf8(v).unwrap_or("<Invalid UTF8>")),
            Value::Opaque(v) => write!(f, "<Opaque: {} bytes>", v.len()),
            Value::NoSuchObject => write!(f, "<NoSuchObject"),
            Value::NoSuchInstance => write!(f, "<NoSuchInstance>"),
            Value::EndOfMIBView => write!(f, "<EndOfMIBView>"),
        }
    }
}

pub type SnmpString = Implicit<OctetString, Utf8String>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Version {
    V1,
    V2C,
    V3,
}

impl AsnType for Version {
    const TAG: Tag = Tag::INTEGER;
}

impl Encode for Version {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        match self {
            Version::V1 => 0.encode_with_tag(encoder, tag),
            Version::V2C => 1.encode_with_tag(encoder, tag),
            Version::V3 => 2.encode_with_tag(encoder, tag),
        }
    }
}

impl Decode for Version {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        let version = i32::decode_with_tag(decoder, Self::TAG)?;
        let result = match version {
            0 => Version::V1,
            1 => Version::V2C,
            2 => Version::V3,
            _ => {
                return Err(D::Error::custom(format!(
                    "Unexpected version {:?}, expected 0-2",
                    version
                )))
            }
        };

        Ok(result)
    }
}

#[macro_export]
macro_rules! oid {
    (
        $($a:expr) , +
    ) => {
        ObjectIdentifier::new(vec![ $($a,)+ ]).unwrap()
    };
}
#[derive(Clone, Debug)]
pub struct VarBinding {
    pub name: ObjectIdentifier,
    pub value: Value,
}

impl VarBinding {
    pub fn new(name: ObjectIdentifier, value: Value) -> VarBinding {
        VarBinding { name, value }
    }

    pub fn null_from(name: ObjectIdentifier) -> VarBinding {
        VarBinding {
            name,
            value: Value::Null,
        }
    }
}

impl AsnType for VarBinding {
    const TAG: Tag = Tag::SEQUENCE;
}
impl Encode for VarBinding {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.name.encode(sequence)?;
            self.value.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for VarBinding {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        let mut seq = decoder.decode_sequence(Self::TAG)?;
        let name = ObjectIdentifier::decode(&mut seq)?;
        let value = Value::decode(&mut seq)?;

        Ok(VarBinding { name, value })
    }
}

impl fmt::Display for VarBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, {})",
            ObjectIdentifierDisplayWrapper(&self.name),
            self.value
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::ber::decode;
    use rasn::ber::encode;

    #[test]
    fn encode_null() {
        let v = Value::Null;
        let b: &[u8] = &[5, 0];
        let e = encode(&v).unwrap();
        assert_eq!(e, b);

        let d = decode::<Value>(b).unwrap();
        assert_eq!(d, v);
    }

    #[test]
    fn encode_oid() {
        let v = Value::Oid(ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1]).unwrap());
        let b: &[u8] = &[6, 5, 43, 6, 1, 2, 1];
        let e = encode(&v).unwrap();
        assert_eq!(e, b);

        let d = decode::<Value>(b).unwrap();
        assert_eq!(d, v);
    }

    #[test]
    fn encode_integer() {
        let v = Value::Integer(5);
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[2, 1, 5]);

        // Ip Address
        let v = Value::IpAddr(Ipv4Addr::new(10, 0, 0, 1));
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[64, 4, 1, 0, 0, 10]);

        // Gauge32
        let v = Value::Gauge32(128);
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[66, 2, 0, 128]);

        // Counter32
        let v = Value::Counter32(1);
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[65, 1, 1]);

        // Counter64
        let v = Value::Counter64(1_u64 << 32);
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[70, 5, 1, 0, 0, 0, 0]);

        // TimeTicks
        let v = Value::Timeticks(TimeTicks::new(1234));
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[67, 2, 4, 210]);

        // OctetString
        let v = Value::OctetStr(OctetString::copy_from_slice(&[3, 4, 5]));
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[4, 3, 3, 4, 5]);

        // Opaque
        let v = Value::Opaque(OctetString::copy_from_slice(&[3, 4, 5]));
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[68, 3, 3, 4, 5]);

        // NoSuchObject
        let v = Value::NoSuchObject;
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[128, 0]);

        // NoSuchInstance
        let v = Value::NoSuchInstance;
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[129, 0]);

        // EndOfMIBView
        let v = Value::EndOfMIBView;
        let r = encode(&v).expect("Can encode nulls");
        assert_eq!(r, &[130, 0]);
    }

    #[test]
    fn encode_version() {
        let v = Version::V2C;
        let r = encode(&v).expect("Can encode");
        assert_eq!(r, &[2, 1, 1])
    }

    #[test]
    fn encode_timeticks() {
        let v = TimeTicks::new(12);
        let r = encode(&v).expect("Can encode");
        assert_eq!(r, &[67, 1, 12])
    }

    #[test]
    fn encode_binding() {
        let v = VarBinding {
            name: ObjectIdentifier::new(vec![1, 2, 3, 4]).unwrap(),
            value: Value::Null,
        };
        let r = encode(&v).expect("Can encode");
        assert_eq!(r, &[48, 7, 6, 3, 42, 3, 4, 5, 0])
    }
}
