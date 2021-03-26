use snmp::{oid, Client, ObjectIdentifier, Version};
use std::net::UdpSocket;

fn main() {
    let mut socket = UdpSocket::bind("0.0.0.0:0").expect("Could not open socket");
    socket.connect("10.0.0.64:161").expect("Failed to connect");

    let mut c = Client::new(Version::V2C, &mut socket);
    let mut oids = vec![oid! {1,3,6}];

    while let Ok(res) = c.get_next(&oids) {
        println!("{}", res[0]);

        oids = res.into_iter().map(|v| v.name).collect();
    }
}
