use crate::pdu::{Message, Pdu, PduTag};
use crate::types::{ObjectIdentifier, Value, VarBinding, Version};

use rand;
use rasn::ber::{decode, encode};

use std::net::UdpSocket;
use std::{collections::HashMap, future::Ready};

pub struct Client<'a> {
    version: Version,
    current_request: i32,
    read_community: &'a str,
    write_community: &'a str,
    socket: &'a mut UdpSocket,
}

impl<'a> Client<'a> {
    pub fn new(version: Version, socket: &'a mut UdpSocket) -> Client<'a> {
        Client {
            version,
            current_request: rand::random::<i32>(),
            read_community: "public",
            write_community: "private",
            socket,
        }
    }

    pub fn set_communities(&mut self, read_community: &'a str, write_community: &'a str) {
        self.read_community = read_community;
        self.write_community = write_community;
    }

    pub fn get(&mut self, oids: &[ObjectIdentifier]) -> Result<Vec<VarBinding>, i32> {
        let request_id = self.increment_request();
        let pdu = Pdu::new(PduTag::GetRequest, request_id).with_null_bindings(oids);

        self.send_and_recv(pdu)
    }

    pub fn get_next(&mut self, oids: &[ObjectIdentifier]) -> Result<Vec<VarBinding>, i32> {
        let request_id = self.increment_request();
        let pdu = Pdu::new(PduTag::GetNextRequest, request_id).with_null_bindings(oids);

        self.send_and_recv(pdu)
    }

    pub fn get_bulk(
        &mut self,
        non_repeating_oids: &[ObjectIdentifier],
        repetitions: i32,
        repeating_oids: &[ObjectIdentifier],
    ) -> Result<Vec<VarBinding>, i32> {
        let request_id = self.increment_request();
        let pdu = Pdu::new(PduTag::GetBulkRequest, request_id)
            .set_bulk_repetitions(non_repeating_oids.len() as i32, repetitions)
            .with_null_bindings(non_repeating_oids)
            .with_null_bindings(repeating_oids);

        self.send_and_recv(pdu)
    }

    pub fn set(&mut self, bindings: &[VarBinding]) -> Result<Vec<VarBinding>, i32> {
        let request_id = self.increment_request();
        let pdu = Pdu::new(PduTag::SetRequest, request_id).with_bindings(bindings);

        self.send_and_recv(pdu)
    }

    fn send_and_recv(&mut self, pdu: Pdu) -> Result<Vec<VarBinding>, i32> {
        let msg = Message::new(self.version, self.read_community, pdu);
        let buf = encode(&msg).map_err(|_| -1)?;
        self.socket.send(&buf).map_err(|_| -2)?;

        let mut recv_buf = [0u8; 1500];
        let size = self.socket.recv(&mut recv_buf).map_err(|_| -3)?;
        let msg = decode::<Message>(&recv_buf[..size]).map_err(|_| -4)?;

        Ok(msg.data().bindings().to_vec())
    }

    fn increment_request(&mut self) -> i32 {
        let request = self.current_request;
        self.current_request += 1;
        request
    }
}
