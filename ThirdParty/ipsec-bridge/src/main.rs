//! Per-attempt, unprivileged IPsec bridge. Secrets only cross anonymous pipes.
use anyhow::{Context, ensure};
use async_trait::async_trait;
use serde_json::{Value, json};
use snxcore::{
    model::{
        MfaType, SessionState,
        params::{TransportType, TunnelParams, TunnelType},
        proto::{
            AuthResponse, CccServerResponse, CertificateResponse, ClientSettingsResponse, GatewayInformation,
            ResponseData,
        },
        wrappers::SessionId,
    },
    sexpr::SExpression,
    tunnel::{GatewayConnector, TunnelCommand, TunnelConnector, TunnelEvent, ipsec::ikev1::Ikev1TunnelConnector},
};
use std::{
    io::{BufRead, Read, Write},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};
static IO: Mutex<()> = Mutex::new(());
fn emit(v: Value) {
    let _lock = IO.lock().unwrap();
    println!("{v}");
    let _ = std::io::stdout().flush();
}
fn read() -> anyhow::Result<Value> {
    let mut b = String::new();
    let n = std::io::stdin().lock().take(1048577).read_line(&mut b)?;
    ensure!(n > 0 && n <= 1048576, "Input closed or oversized");
    Ok(serde_json::from_str(&b)?)
}
async fn rpc(op: &str, fields: Value) -> anyhow::Result<Value> {
    let op = op.to_owned();
    tokio::task::spawn_blocking(move || {
        let _guard = IO.lock().unwrap();
        println!("{}", json!({"rpc":op,"fields":fields}));
        std::io::stdout().flush()?;
        let v = read()?;
        ensure!(v.get("ok") == Some(&Value::Bool(true)), "Parent rejected operation");
        Ok(v["value"].clone())
    })
    .await?
}
fn response(s: &str) -> anyhow::Result<ResponseData> {
    s.parse::<SExpression>()?
        .try_into::<CccServerResponse>()?
        .data
        .into_data()
}
#[derive(Clone)]
struct Gateway {
    info: GatewayInformation,
}
#[async_trait]
impl GatewayConnector for Gateway {
    async fn get_gateway_information(&self) -> anyhow::Result<GatewayInformation> {
        Ok(self.info.clone())
    }
    async fn get_client_settings(&self, _: &SessionId) -> anyhow::Result<ClientSettingsResponse> {
        anyhow::bail!("OS route settings are not used by the packet bridge")
    }
    async fn signout(&self, id: &SessionId) -> anyhow::Result<()> {
        rpc("signout", json!({"session_id":id})).await?;
        Ok(())
    }
    async fn authenticate(&self, _: &str) -> anyhow::Result<AuthResponse> {
        anyhow::bail!("CCC authentication not used by IPsec")
    }
    async fn challenge_code(&self, _: &SessionId, _: &str) -> anyhow::Result<AuthResponse> {
        anyhow::bail!("CCC authentication not used by IPsec")
    }
    async fn enroll_certificate(&self, _: &str, _: &str) -> anyhow::Result<CertificateResponse> {
        anyhow::bail!("Enrollment disabled")
    }
    async fn renew_certificate(&self, _: &[u8], _: &str) -> anyhow::Result<CertificateResponse> {
        anyhow::bail!("Enrollment disabled")
    }
}
// Preserve factor positions: an absent custom label must not shift the next
// factor's label onto the first request. Dynamic gateway prompts take priority.
fn factor_labels(info: &GatewayInformation, realm: &str) -> Vec<Option<String>> {
    use snxcore::model::proto::LoginDisplayLabelSelect;
    let Some(option) = info.get_login_option(realm) else {
        return Vec::new();
    };
    let mut factors: Vec<_> = option.factors.iter().collect();
    factors.sort_by_key(|(key, _)| key.parse::<u32>().unwrap_or(u32::MAX));
    factors
        .into_iter()
        .map(|(_, factor)| {
            if factor.factor_type != "password" {
                return None;
            }
            let LoginDisplayLabelSelect::LoginDisplayLabel(labels) = &factor.custom_display_labels else {
                return None;
            };
            let label = labels.get("password")?.trim();
            if label.is_empty() {
                return None;
            }
            let header = labels.get("header").map(|s| s.trim()).unwrap_or_default();
            Some(if header.is_empty() {
                label.to_owned()
            } else {
                format!("{header}\n{label}")
            })
        })
        .collect()
}
fn challenge_prompt(prompt: &str, labels: &[Option<String>], index: usize) -> String {
    let generic = prompt
        .trim()
        .trim_end_matches(':')
        .trim()
        .eq_ignore_ascii_case("password");
    if generic && let Some(Some(label)) = labels.get(index) {
        return label.clone();
    }
    prompt.to_owned()
}
async fn run() -> anyhow::Result<()> {
    let config = read()?;
    ensure!(
        config["probe"] != true || config["username"] == "",
        "Probe cannot send credentials"
    );
    let address: Ipv4Addr = config["address"].as_str().context("Missing address")?.parse()?;
    let info = match response(
        config["gateway_response"]
            .as_str()
            .context("Missing verified gateway info")?,
    )? {
        ResponseData::ServerInfo(v) => v,
        _ => anyhow::bail!("Invalid gateway capabilities"),
    };
    ensure!(
        info.connectivity_info.client_enabled
            && info
                .connectivity_info
                .supported_data_tunnel_protocols
                .iter()
                .any(|p| p.eq_ignore_ascii_case("IPsec")),
        "Gateway does not permit IPsec"
    );
    ensure!(
        !info.connectivity_info.internal_ca_fingerprint.is_empty(),
        "Missing authenticated IKE CA identity"
    );
    ensure!(info.connectivity_info.tcpt_port == 443, "Unsupported gateway port");
    let params = TunnelParams {
        server_name: address.to_string(),
        user_name: config["username"].as_str().context("Missing username")?.to_owned(),
        login_type: config["realm"].as_str().context("Missing realm")?.to_owned(),
        tunnel_type: TunnelType::IPsec,
        transport_type: TransportType::Tcpt,
        no_routing: true,
        no_dns: true,
        no_keepalive: true,
        mtu: 1400,
        ike_persist: false,
        ignore_server_cert: false,
        ..Default::default()
    };
    ensure!(
        info.is_supported_login_type(&params.login_type),
        "Unadvertised login option"
    );
    ensure!(!info.prefers_ikev2(), "IKEv2 not yet supported by this bridge");
    let labels = factor_labels(&info, &params.login_type);
    let gateway: Arc<dyn GatewayConnector + Send + Sync> = Arc::new(Gateway { info });
    let params = Arc::new(params);
    emit(json!({"stage":"ipsec_negotiating"}));
    let mut connector: Box<dyn TunnelConnector + Send + Sync> =
        Box::new(Ikev1TunnelConnector::new(params.clone(), gateway.clone()).await?);
    let mut session = tokio::time::timeout(Duration::from_secs(45), connector.authenticate()).await??;
    emit(json!({"stage":"ipsec_gateway_verified"}));
    if config["probe"] == true {
        ensure!(params.user_name.is_empty(), "Probe cannot send a username");
        return Ok(());
    }
    let mut factor_index = 0;
    loop {
        match &session.state {
            SessionState::Authenticated(_) => break,
            SessionState::PendingChallenge(c) => {
                ensure!(
                    c.mfa_type == MfaType::PasswordInput || c.mfa_type == MfaType::UserNameInput,
                    "Unsupported IPsec authentication factor"
                );
                let value = if c.mfa_type == MfaType::UserNameInput {
                    Value::String(params.user_name.clone())
                } else {
                    let prompt = challenge_prompt(&c.prompt, &labels, factor_index);
                    factor_index += 1;
                    tokio::time::timeout(Duration::from_secs(180), rpc("challenge", json!({"prompt":prompt}))).await??
                };
                session = tokio::time::timeout(
                    Duration::from_secs(45),
                    connector.challenge_code(session, value.as_str().context("Invalid challenge value")?),
                )
                .await??;
            }
            _ => anyhow::bail!("Missing authentication state"),
        }
    }
    emit(json!({"stage":"authenticated"}));
    let (command_tx, command_rx) = tokio::sync::mpsc::channel(8);
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(32);
    let mut tunnel = tokio::time::timeout(
        Duration::from_secs(30),
        connector.create_tunnel(session.clone(), command_tx.clone()),
    )
    .await??;
    let task = tokio::spawn(async move { tunnel.run(command_rx, event_tx).await });
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut task = task;
    let outcome: anyhow::Result<()> = loop {
        tokio::select! {
         result=&mut task=>{break result?;},
         _=term.recv()=>{let _=command_tx.send(TunnelCommand::Terminate(true)).await;break Ok(());},
         event=event_rx.recv()=>{
          let event=event.context("Tunnel event pipe closed")?;
          if let TunnelEvent::Connected(info)=&event {emit(json!({"stage":"ipsec_connected","address":info.ip_address.addr().to_string(),"dns":info.dns_servers}));}
          if let Err(e)=tokio::time::timeout(Duration::from_secs(30),connector.handle_tunnel_event(event)).await?{break Err(e);}
         }
        }
    };
    let _ = command_tx.send(TunnelCommand::Terminate(true)).await;
    task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway.signout(&session.session_id)).await;
    // The connector sends authenticated IKE deletion on drop, bounded by the parent watchdog.
    drop(connector);
    outcome
}
#[tokio::main]
async fn main() {
    // Do not install a tracing subscriber: upstream debug output includes authentication material.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    // Parent loss must also stop a bridge currently waiting on a password pipe.
    let parent = snxcore::platform::bridge_parent_id();
    if parent <= 1 {
        std::process::exit(2);
    }
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(250));
            if snxcore::platform::bridge_parent_id() != parent {
                std::process::exit(2);
            }
        }
    });
    let result = tokio::select! {r=run()=>Some(r),_=term.recv()=>None};
    // No stdout lock on cancellation: a blocking RPC reader may own that lock.
    let Some(result) = result else { std::process::exit(0) };
    match result {
        Ok(()) => {
            emit(json!({"stage":"disconnected"}));
            std::process::exit(0)
        }
        Err(e) => {
            emit(json!({"stage":"failed","code":"IPSEC_FAILED","detail":e.to_string()}));
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod prompt_tests {
    use super::*;
    use snxcore::model::proto::*;
    use std::collections::BTreeMap;
    fn info(first: Option<&str>) -> GatewayInformation {
        let factor = |label: Option<&str>| LoginFactor {
            factor_type: "password".into(),
            custom_display_labels: match label {
                Some(s) => LoginDisplayLabelSelect::LoginDisplayLabel(BTreeMap::from([("password".into(), s.into())])),
                None => LoginDisplayLabelSelect::Empty(String::new()),
            },
        };
        GatewayInformation {
            protocol_version: ProtocolVersion { protocol_version: 100 },
            connectivity_info: ConnectivityInfo {
                default_authentication_method: None,
                client_enabled: true,
                supported_data_tunnel_protocols: vec!["IPsec".into()],
                connectivity_type: "IPsec".into(),
                server_ip: "192.0.2.1".parse().unwrap(),
                ipsec_transport: "TCPT".into(),
                tcpt_port: 443,
                natt_port: 4500,
                connect_with_certificate_url: String::new(),
                internal_ca_fingerprint: BTreeMap::new(),
            },
            login_options_data: Some(LoginOptionsData {
                login_options_md5: String::new(),
                login_options_list: BTreeMap::from([(
                    "0".into(),
                    LoginOption {
                        id: "fixture".into(),
                        secondary_realm_hash: String::new(),
                        display_name: "Test".into(),
                        show_realm: 1,
                        factors: BTreeMap::from([
                            ("0".into(), factor(first)),
                            ("1".into(), factor(Some("Account password"))),
                        ]),
                    },
                )]),
            }),
        }
    }
    #[test]
    fn generic_password_uses_selected_gateway_factor_labels() {
        let labels = factor_labels(&info(Some("OTP from test token")), "fixture");
        assert_eq!(challenge_prompt("password:", &labels, 0), "OTP from test token");
        assert_eq!(challenge_prompt("Password: ", &labels, 1), "Account password");
        assert_eq!(
            challenge_prompt("Enter recovery code", &labels, 0),
            "Enter recovery code"
        );
        assert_eq!(challenge_prompt("password:", &labels, 2), "password:");
    }
    #[test]
    fn missing_label_does_not_shift_next_factor_or_invent_otp() {
        let labels = factor_labels(&info(None), "fixture");
        assert_eq!(challenge_prompt("password:", &labels, 0), "password:");
        assert_eq!(challenge_prompt("password:", &labels, 1), "Account password");
        assert!(factor_labels(&info(Some("OTP")), "different-realm").is_empty());
    }
}
