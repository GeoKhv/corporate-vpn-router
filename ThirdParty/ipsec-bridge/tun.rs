//! Corporate VPN Router packet transport. No TUN, routes, DNS, or SCV assertions.
use crate::{
    model::{
        ConnectionInfo, TunnelSession,
        params::{TransportType, TunnelParams, TunnelType},
    },
    tunnel::{GatewayConnector, TunnelCommand, TunnelEvent},
    util,
};
use anyhow::{Context, ensure};
use bytes::Bytes;
use chrono::Local;
use futures::{
    SinkExt, StreamExt,
    channel::mpsc::{Receiver, Sender},
};
use isakmp::esp::{EspCodec, EspEncapType};
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};
pub type PacketSender = Sender<Bytes>;
pub type PacketReceiver = Receiver<Bytes>;
pub(crate) struct TunIPsecTunnel {
    params: Arc<TunnelParams>,
    session: Arc<TunnelSession>,
    sender: PacketSender,
    receiver: PacketReceiver,
    gateway: Ipv4Addr,
    keepalive: Ipv4Addr,
    transport: TransportType,
}
fn checksum(data: &[u8]) -> u16 {
    let mut n: u32 = data
        .chunks(2)
        .map(|c| ((c[0] as u32) << 8) + c.get(1).copied().unwrap_or(0) as u32)
        .sum();
    while n >> 16 != 0 {
        n = (n & 65535) + (n >> 16)
    }
    !(n as u16)
}
fn keepalive(src: Ipv4Addr, dst: Ipv4Addr, id: u32) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20..22].copy_from_slice(&491u16.to_be_bytes());
    p[22..24].copy_from_slice(&18234u16.to_be_bytes());
    p[24..26].copy_from_slice(&20u16.to_be_bytes());
    p[28..32].copy_from_slice(&id.to_be_bytes());
    p[32..34].copy_from_slice(&3u16.to_be_bytes());
    p[34..36].copy_from_slice(&2u16.to_be_bytes());
    p[36..38].copy_from_slice(&12u16.to_be_bytes());
    p
}
fn ka_reply(p: &[u8], src: Ipv4Addr, dst: Ipv4Addr, id: u32) -> bool {
    p.len() >= 40
        && p[0] == 0x45
        && p[9] == 17
        && p[12..16] == src.octets()
        && p[16..20] == dst.octets()
        && p[20..22] == 18234u16.to_be_bytes()
        && p[22..24] == 491u16.to_be_bytes()
        && p[28..32] == id.to_be_bytes()
}
impl TunIPsecTunnel {
    pub(crate) async fn create(
        params: Arc<TunnelParams>,
        session: Arc<TunnelSession>,
        sender: PacketSender,
        receiver: PacketReceiver,
        transport: TransportType,
        gateway: Arc<dyn GatewayConnector + Send + Sync>,
    ) -> anyhow::Result<Self> {
        let info = gateway.get_gateway_information().await?;
        let ip = util::server_name_to_ipv4(&params.server_name, info.connectivity_info.tcpt_port)?;
        let keepalive = info.connectivity_info.server_ip;
        // Office Mode address/DNS and ESP keys already come from authenticated IKE.
        // ClientSettings supplies OS route ranges to upstream's TUN implementation.
        // This packet-only bridge neither installs nor consumes those routes.
        ensure!(
            params.no_routing && params.no_dns && !params.default_route,
            "OS configuration prohibited"
        );
        Ok(Self {
            params,
            session,
            sender,
            receiver,
            gateway: ip,
            keepalive,
            transport,
        })
    }
    pub(super) async fn run(
        &mut self,
        mut commands: tokio::sync::mpsc::Receiver<TunnelCommand>,
        events: tokio::sync::mpsc::Sender<TunnelEvent>,
    ) -> anyhow::Result<()> {
        let s = self.session.ipsec_session().context("Missing IPsec session")?.clone();
        ensure!(!s.physical_address, "Office Mode address required");
        ensure!(!s.dns.is_empty(), "Corporate DNS required");
        let device = crate::platform::bridge_packet_socket()?;
        let encap = if self.transport == TransportType::Tcpt {
            EspEncapType::Udp
        } else {
            EspEncapType::None
        };
        let mut incoming = EspCodec::new(self.gateway, s.address, encap);
        incoming.set_params(s.esp_in.spi, s.esp_in.clone());
        let mut outgoing = EspCodec::new(s.address, self.gateway, encap);
        outgoing.set_params(s.esp_out.spi, s.esp_out.clone());
        let info = ConnectionInfo {
            since: Some(Local::now()),
            server_name: self.params.server_name.clone(),
            username: String::new(),
            login_type: self.params.login_type.clone(),
            tunnel_type: TunnelType::IPsec,
            transport_type: s.transport_type,
            ip_address: s.ipv4net_address(),
            dns_servers: s.dns.clone(),
            search_domains: vec![],
            interface_name: String::new(),
            dns_configured: false,
            routing_configured: false,
            default_route: false,
            profile_id: self.params.profile_id,
            profile_name: String::new(),
            live: Default::default(),
            ike_state: None,
        };
        events.send(TunnelEvent::Connected(Box::new(info))).await?;
        let mut rekey = tokio::time::interval(Duration::from_secs(10));
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        let mut next_ka = Instant::now() + Duration::from_secs(20);
        let mut pending: Option<(u32, Instant)> = None;
        let mut seq = 0u32;
        let mut missed = 0;
        let mut buf = vec![0u8; 65536];
        loop {
            tokio::select! {
             cmd=commands.recv()=>match cmd {
              Some(TunnelCommand::Terminate(_))|None=>break,
              Some(TunnelCommand::ReKey(new))=>{
               ensure!(new.address==s.address&&new.dns==s.dns,"IPsec lease changed; reconnect required");
               incoming.add_params(new.esp_in.spi,new.esp_in.clone(),new.lifetime);outgoing.set_params(new.esp_out.spi,new.esp_out.clone());events.send(TunnelEvent::Rekeyed(new)).await?;
              }
             },
             _=rekey.tick()=>{events.send(TunnelEvent::RekeyCheck).await?;},
             _=timer.tick()=>{
              if let Some((_,sent))=pending && sent.elapsed()>Duration::from_secs(2){missed+=1;pending=None;events.send(TunnelEvent::KeepaliveFailed).await?;ensure!(missed<5,"IPsec keepalive failed");next_ka=Instant::now();}
              if pending.is_none()&&Instant::now()>=next_ka {seq=seq.wrapping_add(1);let p=keepalive(s.address,self.keepalive,seq);self.sender.send(outgoing.encode(&p)?).await?;pending=Some((seq,Instant::now()));}
             },
             packet=self.receiver.next()=>{
              let wire=packet.context("IPsec transport closed")?;
              // Ignore unauthenticated/corrupt ESP packets; never forward them to the proxy.
              if let Ok(p)=incoming.decode(&wire){
               if let Some((id,sent))=pending && ka_reply(&p,self.keepalive,s.address,id){pending=None;missed=0;next_ka=Instant::now()+Duration::from_secs(20);events.send(TunnelEvent::Rtt(sent.elapsed())).await?;continue;}
               ensure!(p.len()<=2048,"IPsec packet exceeds proxy buffer");
               tokio::time::timeout(Duration::from_secs(5),device.send(&p)).await??;
              }
             },
             n=device.recv(&mut buf)=>{
              let n=n?;if n==0{continue;}
              ensure!(n<=self.params.mtu as usize&&n>=20&&buf[0]>>4==4,"Invalid proxy IP packet");
              tokio::time::timeout(Duration::from_secs(5),self.sender.send(outgoing.encode(&buf[..n])?)).await??;
             }
            }
        }
        let _ = events.send(TunnelEvent::Disconnected).await;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{proto::*, wrappers::SessionId};
    struct SettingsUnavailable;
    #[async_trait::async_trait]
    impl GatewayConnector for SettingsUnavailable {
        async fn get_gateway_information(&self) -> anyhow::Result<GatewayInformation> {
            Ok(GatewayInformation {
                protocol_version: ProtocolVersion { protocol_version: 100 },
                login_options_data: None,
                connectivity_info: ConnectivityInfo {
                    default_authentication_method: None,
                    client_enabled: true,
                    supported_data_tunnel_protocols: vec!["IPsec".into()],
                    connectivity_type: "IPsec".into(),
                    server_ip: "192.0.2.1".parse()?,
                    ipsec_transport: "TCPT".into(),
                    tcpt_port: 443,
                    natt_port: 4500,
                    connect_with_certificate_url: String::new(),
                    internal_ca_fingerprint: Default::default(),
                },
            })
        }
        async fn get_client_settings(&self, _: &SessionId) -> anyhow::Result<ClientSettingsResponse> {
            panic!("Unused CCC ClientSettings must never be requested")
        }
        async fn authenticate(&self, _: &str) -> anyhow::Result<AuthResponse> {
            unreachable!()
        }
        async fn challenge_code(&self, _: &SessionId, _: &str) -> anyhow::Result<AuthResponse> {
            unreachable!()
        }
        async fn enroll_certificate(&self, _: &str, _: &str) -> anyhow::Result<CertificateResponse> {
            unreachable!()
        }
        async fn renew_certificate(&self, _: &[u8], _: &str) -> anyhow::Result<CertificateResponse> {
            unreachable!()
        }
        async fn signout(&self, _: &SessionId) -> anyhow::Result<()> {
            unreachable!()
        }
    }
    #[tokio::test]
    async fn packet_transport_needs_no_ccc_route_settings() {
        for allowed in [true, false] {
            let params = Arc::new(TunnelParams {
                server_name: "192.0.2.1".into(),
                no_routing: allowed,
                no_dns: true,
                default_route: false,
                ..Default::default()
            });
            let (tx, rx) = futures::channel::mpsc::channel(8);
            let result = TunIPsecTunnel::create(
                params,
                Arc::new(TunnelSession::empty()),
                tx,
                rx,
                TransportType::Tcpt,
                Arc::new(SettingsUnavailable),
            )
            .await;
            if allowed {
                assert!(result.is_ok(), "Packet-only setup failed: {:?}", result.err());
            } else {
                assert!(
                    result
                        .err()
                        .unwrap()
                        .to_string()
                        .contains("OS configuration prohibited")
                );
            }
        }
    }
    #[test]
    fn keepalive_checksums_and_matching() {
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let b = Ipv4Addr::new(192, 0, 2, 2);
        let mut p = keepalive(a, b, 7);
        assert_eq!(checksum(&p[..20]), 0);
        assert!(!ka_reply(&p, a, b, 7));
        p[20..22].copy_from_slice(&18234u16.to_be_bytes());
        p[22..24].copy_from_slice(&491u16.to_be_bytes());
        assert!(ka_reply(&p, a, b, 7));
        assert!(!ka_reply(&p, a, b, 8));
        assert!(!ka_reply(&p, b, a, 7));
    }
}
