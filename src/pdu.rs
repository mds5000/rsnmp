use crate::types::{SnmpString, VarBinding, Version};

use rasn::de::Error;
use rasn::types::{Class, ObjectIdentifier};
use rasn::{AsnType, Decode, Decoder, Encode, Encoder, Tag};

const TAG_MSG_GET: Tag = Tag::new(Class::Context, 0);
const TAG_MSG_GETNEXT: Tag = Tag::new(Class::Context, 1);
const TAG_MSG_RESPONSE: Tag = Tag::new(Class::Context, 2);
const TAG_MSG_SET: Tag = Tag::new(Class::Context, 3);
const TAG_MSG_TRAPV1: Tag = Tag::new(Class::Context, 4);
const TAG_MSG_GETBULK: Tag = Tag::new(Class::Context, 5);
const TAG_MSG_INFORM: Tag = Tag::new(Class::Context, 6);
const TAG_MSG_TRAPV2: Tag = Tag::new(Class::Context, 7);
const TAG_MSG_REPORT: Tag = Tag::new(Class::Context, 8);

#[derive(Debug)]
pub struct Message {
    version: Version,
    community: String,
    data: Pdu,
}

impl Message {
    pub fn new(version: Version, community: &str, data: Pdu) -> Self {
        Message {
            version,
            community: community.to_owned(),
            data,
        }
    }

    pub fn data(&self) -> &Pdu {
        &self.data
    }
}

impl AsnType for Message {
    const TAG: Tag = Tag::SEQUENCE;
}
impl<'a> Encode for Message {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.version.encode(sequence)?;
            SnmpString::new(self.community.clone()).encode(sequence)?;
            self.data.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Message {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        let mut seq = decoder.decode_sequence(Self::TAG)?;
        let version = Version::decode(&mut seq)?;
        let community = (*SnmpString::decode(&mut seq)?).clone();
        let data = Pdu::decode(&mut seq)?;

        Ok(Message {
            version,
            community,
            data,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PduTag {
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    Trap,           //V1
    GetBulkRequest, //BULK
    InformRequest,
    TrapV2, //V2
    Report,
}

impl PduTag {
    fn into_tag(&self) -> Tag {
        match &self {
            PduTag::GetRequest => TAG_MSG_GET,
            PduTag::GetNextRequest => TAG_MSG_GETNEXT,
            PduTag::GetResponse => TAG_MSG_RESPONSE,
            PduTag::SetRequest => TAG_MSG_SET,
            PduTag::Trap => TAG_MSG_TRAPV1,
            PduTag::GetBulkRequest => TAG_MSG_GETBULK,
            PduTag::InformRequest => TAG_MSG_INFORM,
            PduTag::TrapV2 => TAG_MSG_TRAPV2,
            PduTag::Report => TAG_MSG_REPORT,
        }
    }

    fn from_tag(tag: Tag) -> Result<Self, ()> {
        let res = match tag {
            TAG_MSG_GET => PduTag::GetRequest,
            TAG_MSG_GETNEXT => PduTag::GetNextRequest,
            TAG_MSG_RESPONSE => PduTag::GetResponse,
            TAG_MSG_SET => PduTag::SetRequest,
            TAG_MSG_TRAPV1 => PduTag::Trap,
            TAG_MSG_GETBULK => PduTag::GetBulkRequest,
            TAG_MSG_INFORM => PduTag::InformRequest,
            TAG_MSG_TRAPV2 => PduTag::TrapV2,
            TAG_MSG_REPORT => PduTag::Report,
            _ => return Err(()),
        };

        Ok(res)
    }
}

#[derive(Debug)]
pub struct Pdu {
    tag: PduTag,
    request_id: i32,
    err_status: i32,
    err_index: i32,
    bindings: Vec<VarBinding>,
}

impl Pdu {
    pub fn new(tag: PduTag, request_id: i32) -> Pdu {
        Pdu {
            tag,
            request_id,
            err_status: 0,
            err_index: 0,
            bindings: vec![],
        }
    }

    pub fn with_error(mut self, err_status: i32, err_index: i32) -> Self {
        self.err_status = err_status;
        self.err_index = err_index;
        self
    }

    pub fn with_bindings(mut self, bindings: &[VarBinding]) -> Self {
        self.bindings.extend_from_slice(bindings);
        self
    }

    pub fn with_null_bindings(mut self, bindings: &[ObjectIdentifier]) -> Self {
        self.bindings.extend(
            bindings
                .into_iter()
                .map(|b| VarBinding::null_from(b.clone())),
        );
        self
    }

    pub fn set_bulk_repetitions(mut self, num_repeaters: i32, max_repititions: i32) -> Self {
        self.err_status = num_repeaters;
        self.err_index = max_repititions;
        self
    }

    pub fn tag(&self) -> PduTag {
        self.tag
    }

    pub fn error(&self) -> Result<(), i32> {
        if self.err_status == 0 {
            return Ok(());
        }

        Err(self.err_status)
    }

    pub fn bindings(&self) -> &[VarBinding] {
        &self.bindings
    }
}

impl AsnType for Pdu {
    const TAG: Tag = Tag::SEQUENCE;
}

impl Encode for Pdu {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(self.tag.into_tag(), |sequence| {
            self.request_id.encode(sequence)?;
            self.err_status.encode(sequence)?;
            self.err_index.encode(sequence)?;
            self.bindings.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Pdu {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        let pdu_tag = decoder.peek_tag()?;
        let tag = PduTag::from_tag(pdu_tag)
            .map_err(|_| D::Error::custom(format!("Unexpected PDU Tag {:?}", pdu_tag)))?;

        let mut seq = decoder.decode_sequence(pdu_tag)?;
        let request_id = i32::decode(&mut seq)?;
        let err_status = i32::decode(&mut seq)?;
        let err_index = i32::decode(&mut seq)?;

        let bindings: Vec<VarBinding> = seq.decode_sequence_of(VarBinding::TAG)?;

        Ok(Pdu {
            tag,
            request_id,
            err_status,
            err_index,
            bindings,
        })
    }
}

/* TODO: V1 support
struct TrapV1 {
    enterprise: ObjectIdentifier,
    agent_address: Ipv4Addr,
    generic_trap: i32,
    specific_trap: i32,
    time_stamp: TimeTicks,
    bindings: Vec<VarBinding>,
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Value;
    use rasn::ber::encode;

    #[test]
    fn encode_pdu() {
        let v = Pdu::new(PduTag::GetRequest, 0);
        let r = encode(&v).expect("Can encode");
        assert_eq!(r, &[160, 11, 2, 1, 0, 2, 1, 0, 2, 1, 0, 48, 0])
    }

    #[test]
    fn encode_pdu_with_null_bindings() {
        let oids = vec![oid! {1,2,3}];
        let v = Pdu::new(PduTag::GetRequest, 0).with_null_bindings(&oids);
        let r = encode(&v).expect("Can encode");
        assert_eq!(
            r,
            &[160, 19, 2, 1, 0, 2, 1, 0, 2, 1, 0, 48, 8, 48, 6, 6, 2, 42, 3, 5, 0]
        )
    }

    #[test]
    fn encode_pdu_with_bindings() {
        let vb = VarBinding::new(oid! {1,2,3}, Value::Integer(5));
        let vbs = vec![vb];
        let v = Pdu::new(PduTag::GetRequest, 0).with_bindings(&vbs);
        let r = encode(&v).expect("Can encode");
        assert_eq!(
            r,
            &[160, 20, 2, 1, 0, 2, 1, 0, 2, 1, 0, 48, 9, 48, 7, 6, 2, 42, 3, 2, 1, 5]
        )
    }

    #[test]
    fn encode_message() {
        let pdu = Pdu::new(PduTag::GetNextRequest, 1);
        let msg = Message::new(Version::V3, "public", pdu);
        let r = encode(&msg).unwrap();
        assert_eq!(
            r,
            &[
                48, 24, 2, 1, 2, 4, 6, 112, 117, 98, 108, 105, 99, 161, 11, 2, 1, 1, 2, 1, 0, 2, 1,
                0, 48, 0
            ]
        )
    }
}
