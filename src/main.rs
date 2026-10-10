//! CE owns transport and authorization. This client owns desired state and readiness.
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, HashSet}, env, fs::{self, File, OpenOptions},
    io::{Read, Write}, net::{IpAddr, SocketAddr, TcpStream}, path::{Path, PathBuf},
    process::ExitCode, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}},
    thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
struct Error { code: &'static str, detail: String }
fn err(code: &'static str, detail: impl Into<String>) -> Error { Error {code, detail: detail.into()} }
fn now() -> f64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64() }
fn expand(path: &str) -> PathBuf {
    if let Some(tail) = path.strip_prefix("~/") { home().join(tail) } else { PathBuf::from(path) }
}
fn home() -> PathBuf { PathBuf::from(env::var_os("HOME").unwrap_or_default()) }
fn load<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    let raw = fs::read(path).map_err(|_| err("local_io", "Cannot read configuration or state"))?;
    if raw.len() > 1024*1024 { return Err(err("oversized_state", "Configuration or state exceeds one MiB")); }
    serde_json::from_slice(&raw).map_err(|_| err("invalid_json", "Malformed configuration or state"))
}
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn save<T: Serialize>(path: &Path, data: &T) -> Result<()> {
    let parent = path.parent().ok_or_else(|| err("local_io", "State path has no parent"))?;
    fs::create_dir_all(parent).map_err(|_| err("local_io", "Cannot create state directory"))?;
    let tmp = parent.join(format!(".write-{}-{}", std::process::id(), SEQUENCE.fetch_add(1,Ordering::Relaxed)));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)
            .map_err(|_| err("local_io", "Cannot create private state file"))?;
        serde_json::to_writer_pretty(&mut file, data).map_err(|_| err("local_io", "Cannot encode state"))?;
        file.write_all(b"\n").and_then(|_| file.sync_all()).map_err(|_| err("local_io", "Cannot sync state"))?;
        fs::rename(&tmp,path).map_err(|_| err("local_io", "Cannot atomically save state"))?;
        File::open(parent).and_then(|d| d.sync_all()).map_err(|_| err("local_io", "Cannot sync state directory"))
    })();
    // Remove only the temporary file this invocation created.
    if result.is_err() { let _ = fs::remove_file(&tmp); }
    result
}
fn lock(path: &Path, timeout: Duration) -> Result<File> {
    fs::create_dir_all(path.parent().unwrap()).map_err(|_| err("local_io", "Cannot create lock directory"))?;
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(path)
        .map_err(|_| err("local_io", "Cannot open lock"))?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(25)),
            Err(std::fs::TryLockError::WouldBlock) => return Err(err("busy", "Another ce-net operation holds this state lock")),
            Err(_) => return Err(err("local_io", "Cannot acquire state lock")),
        }
    }
}
fn secret(path: &str) -> Result<String> {
    let path = expand(path);
    let metadata = fs::metadata(&path).map_err(|_| err("missing_credential", "Credential file unavailable"))?;
    if metadata.permissions().mode() & 0o077 != 0 { return Err(err("unsafe_secret_permissions", "Credential file must be private (chmod 600)")); }
    if metadata.len() > 65536 { return Err(err("missing_credential", "Credential file too large")); }
    let value = fs::read_to_string(path).map_err(|_| err("missing_credential", "Credential file unreadable"))?.trim().to_string();
    if value.is_empty() || value.contains(['\r','\n']) { return Err(err("missing_credential", "Credential file empty or malformed")); }
    Ok(value)
}
fn default_url() -> String { "http://127.0.0.1:8844".into() }
fn default_token() -> String {
    home().join(if cfg!(target_os="macos") {"Library/Application Support/ce/api.token"} else {".local/share/ce/api.token"}).to_string_lossy().into()
}
fn timeout() -> f64 { 3.0 }
#[derive(Clone, Deserialize, Serialize)]
struct Probe { kind: String, contains: String, #[serde(default)] path: String, #[serde(default)] negative_path: String }
#[derive(Clone, Deserialize, Serialize)]
struct Service { node_id: String, cap_file: String, local_port: u16, remote_port: u16,
    #[serde(default="timeout")] timeout: f64, probe: Probe }
#[derive(Clone, Deserialize, Serialize)]
struct Config { version: u8, #[serde(default="default_url")] node_url: String,
    #[serde(default="default_token")] token_file: String, services: BTreeMap<String,Service> }
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct Identity { node_id: String, local_port: u16, remote_port: u16 }
impl Service {
    fn identity(&self) -> Identity { Identity {node_id:self.node_id.clone(),local_port:self.local_port,remote_port:self.remote_port} }
}
impl Config {
    fn read(path: &Path) -> Result<Self> { let c:Self=load(path)?; c.validate()?; Ok(c) }
    fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.node_url).map_err(|_| err("unsafe_node_url","Invalid node URL"))?;
        let ip:IpAddr = url.host_str().unwrap_or("").trim_matches(['[',']']).parse()
            .map_err(|_| err("unsafe_node_url","CE API must be a loopback IP origin"))?;
        if !ip.is_loopback() || url.scheme()!="http" || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || url.path()!="/" {
            return Err(err("unsafe_node_url","CE API must be an HTTP loopback IP origin"));
        }
        if self.version!=1 || self.services.len()>128 { return Err(err("invalid_config","Expected version1 and at most128 services")); }
        let mut ports=HashSet::new();
        for (name,s) in &self.services {
            if name.is_empty() || name.len()>63 || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)) || !name.as_bytes()[0].is_ascii_alphanumeric() {
                return Err(err("invalid_config","Invalid service name"));
            }
            if s.node_id.len()!=64 || !s.node_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) || s.cap_file.is_empty() || s.local_port<1024 || s.remote_port==0 || !ports.insert(s.local_port) {
                return Err(err("invalid_config","Invalid endpoint identity, ports or capability path"));
            }
            if !(0.1..=15.0).contains(&s.timeout) || s.probe.contains.is_empty() || s.probe.contains.len()>4096 {
                return Err(err("invalid_config","Invalid probe timeout or expected marker"));
            }
            if s.probe.kind=="http" {
                for p in [&s.probe.path,&s.probe.negative_path] {
                    if !p.starts_with('/') || p.starts_with("//") || p.chars().any(char::is_control) || p.contains('#') {
                        return Err(err("invalid_config","HTTP probe requires health and negative-control paths"));
                    }
                }
            } else if s.probe.kind!="banner" { return Err(err("invalid_config","Unsupported probe kind")); }
        }
        Ok(())
    }
}
fn http(url: &str, method: &str, body: Option<Value>, token: Option<String>, seconds: f64) -> Result<(u16,Vec<u8>)> {
    let client=Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs_f64(seconds)).build().map_err(|_| err("client_error","Cannot build HTTP client"))?;
    let mut request=if method=="POST" { client.post(url) } else { client.get(url) };
    if let Some(t)=token { request=request.bearer_auth(t); }
    if let Some(b)=body { request=request.json(&b); }
    let response=request.send().map_err(|_| err("unreachable","Endpoint did not answer within its deadline"))?;
    let status=response.status().as_u16();
    let mut bytes=Vec::new();
    response.take(1024*1024+1).read_to_end(&mut bytes).map_err(|_| err("unreachable","Response did not complete within its deadline"))?;
    if bytes.len()>1024*1024 { return Err(err("oversized_response","Response exceeds one MiB")); }
    Ok((status,bytes))
}
fn node<T: for<'a> Deserialize<'a>>(c:&Config,path:&str,body:Option<Value>) -> Result<T> {
    let (status,bytes)=http(&format!("{}{}",c.node_url.trim_end_matches('/'),path),if body.is_some(){"POST"}else{"GET"},body,Some(secret(&c.token_file)?),5.0)?;
    match status { 200=>{},401|403=>return Err(err("denied","CE API refused authorization")),404=>return Err(err("unsupported",format!("CE node does not implement {path}"))),_=>return Err(err("node_error",format!("CE API returned HTTP {status}"))) }
    serde_json::from_slice(&bytes).map_err(|_| err("invalid_response","CE API returned malformed or unexpected JSON"))
}
fn probe(s:&Service) -> Result<()> {
    let marker=s.probe.contains.as_bytes();
    let good=if s.probe.kind=="http" {
        let base=format!("http://127.0.0.1:{}",s.local_port);
        let (status,body)=http(&(base.clone()+&s.probe.path),"GET",None,None,s.timeout)?;
        let (negative,_)=http(&(base+&s.probe.negative_path),"GET",None,None,s.timeout)?;
        status==200 && negative==404 && body.windows(marker.len()).any(|v|v==marker)
    } else {
        let address=SocketAddr::from(([127,0,0,1],s.local_port));
        let mut socket=TcpStream::connect_timeout(&address,Duration::from_secs_f64(s.timeout)).map_err(|_|err("upstream_down","No server banner"))?;
        socket.set_read_timeout(Some(Duration::from_secs_f64(s.timeout))).map_err(|_|err("upstream_down","Cannot set banner deadline"))?;
        let mut bytes=[0;4096];
        let n=socket.read(&mut bytes).map_err(|_|err("upstream_down","No server banner"))?;
        bytes[..n].windows(marker.len()).any(|v|v==marker)
    };
    if good { Ok(()) } else { Err(err("upstream_down","Upstream identity or negative-control probe failed")) }
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
struct Entry { desired:bool, identity:Option<Identity>, status:String, code:String, detail:String,
    observed_at:f64, retry_at:f64, failures:u32, elapsed_ms:f64, #[serde(skip_serializing_if="Option::is_none")] stale:Option<bool> }
#[derive(Deserialize, Serialize)]
struct State { version:u8, services:BTreeMap<String,Entry> }
fn state(dir:&Path) -> Result<State> {
    let path=dir.join("state.json");
    if !path.exists() { return Ok(State{version:1,services:BTreeMap::new()}); }
    let s:State=load(&path)?;
    if s.version!=1 { return Err(err("invalid_state","Unsupported state version")); }
    Ok(s)
}
fn ensure(c:&Config,s:&Service,e:&mut Entry) -> Result<()> {
    let identity=s.identity();
    if e.identity.as_ref().is_some_and(|old|old!=&identity) { return Err(err("config_changed","Active endpoint configuration changed")); }
    let rows:Vec<Identity>=node(c,"/tunnels",None)?;
    let held:Vec<_>=rows.iter().filter(|r|r.local_port==s.local_port).collect();
    if held.iter().any(|r|**r!=identity) { return Err(err("port_conflict","Local port belongs to another CE endpoint")); }
    if held.is_empty() {
        if TcpStream::connect_timeout(&SocketAddr::from(([127,0,0,1],s.local_port)),Duration::from_millis(100)).is_ok() {
            return Err(err("port_conflict","Local listener is outside the CE tunnel registry"));
        }
        let created:Identity=node(c,"/tunnel",Some(json!({"node_id":s.node_id,"local_port":s.local_port,"remote_port":s.remote_port,"caps":secret(&s.cap_file)?})))?;
        if created!=identity { return Err(err("invalid_response","CE returned a different tunnel identity")); }
    }
    e.identity=Some(identity);
    probe(s)
}
fn tick(c:&Config,dir:&Path,names:&[String],enable:bool,force:bool) -> Result<State> {
    let _lock=lock(&dir.join("state.lock"),Duration::from_secs(30))?;
    let mut state=state(dir)?;
    for name in names {
        if !c.services.contains_key(name) { return Err(err("unknown_service","Requested service is not configured")); }
        if enable { state.services.entry(name.clone()).or_default().desired=true; }
    }
    save(&dir.join("state.json"),&state)?;
    for name in names {
        let e=state.services.entry(name.clone()).or_default();
        if !e.desired || (!force && now()<e.retry_at) {continue;}
        let started=Instant::now();
        match ensure(c,&c.services[name],e) {
            Ok(())=>{e.status="up".into();e.code="ok".into();e.detail="Expected upstream marker received".into();e.failures=0;},
            Err(f)=>{e.status=if f.code=="unsupported"{"unknown"}else{"down"}.into();e.code=f.code.into();e.detail=f.detail;e.failures=(e.failures+1).min(20);}
        }
        e.observed_at=now();e.elapsed_ms=started.elapsed().as_secs_f64()*1000.0;e.stale=None;
        let jitter=0.8+(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos()%400) as f64/1000.0;
        e.retry_at=e.observed_at+if e.failures==0{5.0}else{(2u32.pow(e.failures).min(60) as f64)*jitter};
        save(&dir.join("state.json"),&state)?;
    }
    Ok(state)
}
fn summary(s:&State)->u8 {
    if s.services.values().any(|e|e.desired&&e.status=="unknown"){2}
    else if s.services.values().any(|e|e.desired&&e.status!="up"){1}else{0}
}
fn run()->Result<u8> {
    let mut args=env::args().skip(1).collect::<Vec<_>>();
    let mut cfg=home().join(".config/ce-tailnet/config.json");
    let mut dir=home().join(".local/state/ce-tailnet");
    while args.first().is_some_and(|a| a=="--config"||a=="--state-dir") {
        if args.len()<2 {return Err(err("usage","Option requires a path"));}
        let flag=args.remove(0);let value=expand(&args.remove(0));
        if flag=="--config"{cfg=value}else{dir=value};
    }
    let command=args.first().map(String::as_str).unwrap_or("--help");
    if command=="--version" {println!("{}",env!("CARGO_PKG_VERSION"));return Ok(0);}
    if command=="--help"||command=="help" {println!("ce-net [--config FILE] [--state-dir DIR] init|doctor|up [SERVICE...]|down [SERVICE...]|status|check|port SERVICE|watch");return Ok(0);}
    if command=="init" {
        let _lock=lock(&cfg.with_extension("json.lock"),Duration::from_secs(30))?;
        if cfg.exists(){return Err(err("config_exists","Existing configuration preserved"));}
        save(&cfg,&Config{version:1,node_url:default_url(),token_file:default_token(),services:BTreeMap::new()})?;
        println!("{}",json!({"config":cfg,"services":0}));return Ok(0);
    }
    let c=Config::read(&cfg)?;
    let names=if args.len()>1{args[1..].to_vec()}else{c.services.keys().cloned().collect()};
    let result=match command {
        "doctor"=>{let _:Value=node(&c,"/status",None)?;let _:Vec<Identity>=node(&c,"/tunnels",None)?;
            println!("{}",json!({"status":"ready","services":c.services.len(),"detail":"Node and registry answered; upstreams not yet measured"}));return Ok(0);},
        "up"|"check"|"port"=>{
            if command=="port" && args.len()<2{return Err(err("usage","port requires a service name"));}
            let result=tick(&c,&dir,&names,command!="check",true)?;
            if command=="port"{
                if summary(&result)!=0 || names.iter().any(|n| result.services[n].status!="up") {return Err(err("not_ready","Requested service has not passed its probe"));}
                for name in &names{println!("127.0.0.1:{}",c.services[name].local_port);}return Ok(0);
            }result
        },
        "status"=>{let mut s=state(&dir)?;for e in s.services.values_mut(){let stale=now()-e.observed_at>90.0;e.stale=Some(stale);if stale{e.status="unknown".into();}}s},
        "down"=>{let _lock=lock(&dir.join("state.lock"),Duration::from_secs(30))?;let mut s=state(&dir)?;
            for name in &names{if !c.services.contains_key(name){return Err(err("unknown_service","Requested service is not configured"));}}
            for name in names{let e=s.services.entry(name).or_default();e.desired=false;e.status="unmanaged".into();e.detail="Recovery disabled; shared CE tunnel left intact".into();}
            save(&dir.join("state.json"),&s)?;s
        },
        "watch"=>{
            let _watch=lock(&dir.join("watch.lock"),Duration::ZERO)?;
            let stop=Arc::new(AtomicBool::new(false));
            for signal in [signal_hook::consts::SIGTERM,signal_hook::consts::SIGINT]{signal_hook::flag::register(signal,stop.clone()).map_err(|_|err("local_io","Cannot install stop handler"))?;}
            while !stop.load(Ordering::Relaxed){let fresh=Config::read(&cfg)?;let names=fresh.services.keys().cloned().collect::<Vec<_>>();
                println!("{}",serde_json::to_string(&tick(&fresh,&dir,&names,false,false)?).unwrap());
                for _ in 0..10{if stop.load(Ordering::Relaxed){break;}thread::sleep(Duration::from_millis(100));}
            }return Ok(0);
        },
        _=>return Err(err("usage","Unknown command; run ce-net --help")),
    };
    println!("{}",serde_json::to_string_pretty(&result).unwrap());Ok(summary(&result))
}
fn main()->ExitCode {
    match run(){Ok(code)=>ExitCode::from(code),Err(e)=>{eprintln!("{}",json!({"status":if e.code=="unsupported"{"unknown"}else{"failed"},"code":e.code,"detail":e.detail}));ExitCode::from(if e.code=="unsupported"{2}else{1})}}
}
