use snmp::{oid, Client, Message, Version};
use std::net::UdpSocket;

use rasn::ber::{decode, encode};
use rasn::types::ObjectIdentifier;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Could not open socket");
    socket.connect("10.0.0.64:161").expect("Failed to connect");

    let mut client = Client::new(Version::V2C, "public");
    let root = vec![oid! {1,3,6}];
    let bytes = encode(&client.get(&root)).unwrap();

    socket.send(&bytes).expect("send");
    let mut buf = [0; 1024];
    let size = socket.recv(&mut buf).unwrap();

    let msg = decode::<Message>(&buf[..size]).unwrap();

    dbg! {&buf[..size]};
    dbg! {msg};
}
