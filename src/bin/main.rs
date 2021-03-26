use snmp::{Client, ObjectIdentifier, SNMP_PORT, Version, oid};
use std::net::{SocketAddrV4, UdpSocket};
use std::net::Ipv4Addr;
use std::env;

fn main() {
    let mut socket = UdpSocket::bind("0.0.0.0:0").expect("Could not open socket");
    let addr: Ipv4Addr = env::args().collect::<Vec<_>>()[1].parse().expect("Not an IP Addr");
    socket.connect(SocketAddrV4::new(addr, SNMP_PORT)).expect("Failed to connect");

    let mut c = Client::new(Version::V2C, &mut socket);
    let mut oids = vec![oid! {1,3,6}];

    let mut last_oid = &oids[oids.len()-1];
    let mut vars = c.get_next(&oids).expect("No data returned");
    while &vars.last().unwrap().name != last_oid {
        println!("{}", vars[0]);

        oids = vars.into_iter().map(|v| v.name).collect();
        last_oid = &oids[oids.len()-1];
        vars = c.get_next(&oids).expect("No data returned");
    }
}
