use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::SystemTime};

use eyre::{bail, eyre, Result};
use hickory_resolver::Name;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinSet};
use warp::{filters::{host::Authority, path::FullPath}, http::Uri, Filter};

#[derive(Deserialize,Serialize)]
pub struct Config {
    pub bind: String,
    pub admin_bind: String,
    pub db: String,
    pub use_tld: String,
    pub stale_timeout_sec: u64,
    pub check_interval_sec: u64,
}

#[derive(Serialize,Deserialize,Default)]
struct Db {
    names: HashMap<String, u64>,
}

type Resolver = hickory_resolver::Resolver<
    hickory_resolver::name_server::GenericConnector<
        hickory_resolver::proto::runtime::TokioRuntimeProvider
    >
>;

struct ServerMut {
    db: Db,
    bounce_mappings: HashMap<String, Uri>,
}

struct Server {
    m: RwLock<ServerMut>,
    config: Config,
    resolver: Resolver,
}

async fn check_txt_record(s: Arc<Server>, domain: String) -> Result<(String, Vec<String>)> {
    // Use hickory-resolver to get the TXT record for the domain
    Ok(s.resolver.txt_lookup(Name::from_ascii(&domain)?).await.map(|response| {
        let txts: Vec<String> = response.iter().map(|txt| {
            txt.txt_data().iter()
                .map(|d| String::from_utf8_lossy(d).to_string())
                .collect::<Vec<_>>()
                .join("")
        }).collect();
        (domain, txts)
    })?)
}

fn handle_txt_record(domain: &str, txts: Vec<String>) -> Result<Uri> {
    if let Some((pos, txt)) = txts.into_iter().filter_map(|t|{
        t.find("BOUNCE=").map(|pos| (pos, t))
    }).next() {
        let bounce = &txt[pos + 7..];
        let bounce = bounce.split_whitespace().next().unwrap_or("");
        println!("Found bounce record for {} => {}", domain, bounce);
        let bounce = match bounce.parse::<Uri>() {
            Ok(b) => b,
            Err(e) => {
                bail!("Invalid bounce URI for {}: {}", domain, e);
            }
        };
        Ok(bounce)
    } else {
        bail!("No bounce record found for {}, removing from db", domain);
    }
}

async fn check_all_records(s: &Arc<Server>) -> Result<()> {
    let names: Vec<String> = {
        let r = s.m.read().await;
        r.db.names.iter().map(|(n,_)|n.clone()).collect()
    };
    let mut js = JoinSet::new();
    for name in names.into_iter() {
        let s = Arc::clone(s);
        js.spawn(check_txt_record(s, name));
    }
    let mut bounce_mappings = HashMap::new();
    let mut remove_names = Vec::new();
    while let Some(res) = js.join_next().await {
        let res = res?;
        let (domain, txts) = match res {
            Ok(r) => r,
            Err(e) => {
                println!("Error checking TXT record: {}", e);
                continue;
            }
        };
        match handle_txt_record(&domain, txts) {
            Ok(uri) => {
                bounce_mappings.insert(domain.clone(), uri);
            }
            Err(e) => {
                println!("Error handling TXT record: {}", e);
                remove_names.push(domain.clone());
            }
        }
    }
    {
        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let mut m = s.m.write().await;
        // Update mappings and timestamps
        for (k, v) in bounce_mappings.into_iter() {
            m.db.names.insert(k.clone(), now);
            m.bounce_mappings.insert(k, v);
        }
        // Remove stale entries
        for (name, &timestamp) in m.db.names.iter() {
            if now.saturating_sub(timestamp) > s.config.stale_timeout_sec {
                println!("Removing stale entry for {}", name);
                remove_names.push(name.clone());
            }
        }
        for name in remove_names.into_iter() {
            m.bounce_mappings.remove(&name);
            m.db.names.remove(&name);
        }
    }
    Ok(())
}

async fn handle_http_req(
    s: Arc<Server>,
    host: Option<Authority>,
    path: FullPath,
    _query: String,
) -> Result<Uri> {
    let Some(host) = host else {
        bail!("No Host header provided");
    };
    let hostname = host.host();
    let m = s.m.read().await;
    let Some(bounce) = m.bounce_mappings.get(host.host()) else {
        bail!("No bounce record found for domain {}", hostname);
    };
    let Some(authority) = bounce.authority() else {
        bail!("Invalid bounce entry (missing hostname): {}", bounce.to_string());
    };
    let Some(scheme) = bounce.scheme() else {
        bail!("Invalid bounce entry (missing scheme, e.g. https://): {}", bounce.to_string());
    };
    let u = Uri::builder()
        .authority(authority.clone())
        .scheme(scheme.clone())
        .path_and_query(path.as_str())
        .build()?;
    Ok(u)
}

async fn warp_task(s: Arc<Server>, sa: SocketAddr) -> Result<()> {
    let get_domains = {
        let s = Arc::clone(&s);
        warp::any().map(move || Arc::clone(&s))
            .and(warp::host::optional())
            .and(warp::path::full())
            .and(warp::query::raw())
            .and_then(|s: Arc<Server>, host: Option<Authority>, path: FullPath, query: String| async move {
                let b: Box<dyn warp::Reply> = match handle_http_req(s, host, path, query).await {
                    Ok(r) => Box::new(warp::redirect::temporary(r)),
                    Err(e) => {
                        Box::new(warp::reply::with_status(
                            format!(
                                    r#"<html>
                                        <head><title>bounce.pkt</title></head>
                                        <body>
                                        <h1>Incorrectly Configured Bounce</h1>
                                        <p><strong>Error with bounce configuration:</strong>{e}</p>
                                        </body>
                                        </html>
                                    "#, e = e.to_string()),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ))
                    }
                };
                Ok::<_, warp::Rejection>(b)
            })
    };

    warp::serve(get_domains).bind(sa).await;

    Ok(())
}

#[derive(Serialize,Deserialize)]
struct CheckDomainResponse {
    domain: String,
    bounce: Option<String>,
    error: Option<String>,
}

async fn check_domain(s: Arc<Server>, domain: String) -> Result<Box<dyn warp::Reply>, Infallible> {
    let (domain, txts) = match check_txt_record(Arc::clone(&s), domain.clone()).await {
        Ok(rec) => rec,
        Err(e) => {
            let resp = CheckDomainResponse {
                domain,
                bounce: None,
                error: Some(e.to_string()),
            };
            let json = serde_json::to_string(&resp)
                .unwrap_or_else(|_|"failed to serialize".to_string());
            return Ok(Box::new(warp::reply::with_status(
                json,
                warp::http::StatusCode::OK,
            )));
        }
    };
    let bounce = match handle_txt_record(&domain, txts) {
        Ok(uri) => uri,
        Err(e) => {
            let resp = CheckDomainResponse {
                domain,
                bounce: None,
                error: Some(e.to_string()),
            };
            let json = serde_json::to_string(&resp)
                .unwrap_or_else(|_|"failed to serialize".to_string());
            return Ok(Box::new(warp::reply::with_status(
                json,
                warp::http::StatusCode::OK,
            )));
        }
    };
    {
        let mut m = s.m.write().await;
        m.db.names.insert(
            domain.clone(),
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        );
        m.bounce_mappings.insert(domain.clone(), bounce.clone());
    }
    let resp = CheckDomainResponse {
        domain,
        bounce: Some(bounce.to_string()),
        error: None,
    };
    let json = serde_json::to_string(&resp)
        .unwrap_or_else(|_|"failed to serialize".to_string());
    Ok(Box::new(warp::reply::with_status(
        json,
        warp::http::StatusCode::OK,
    )))
}

async fn domains(s: Arc<Server>) -> Result<Box<dyn warp::Reply>, Infallible> {
    let m = s.m.read().await;
    let names: Vec<(String, String)> = m.bounce_mappings.iter()
        .map(|(k, v)| (k.clone(), v.to_string())).collect();
    let json = serde_json::to_string(&names)
        .unwrap_or_else(|_|"failed to serialize".to_string());
    Ok(Box::new(warp::reply::with_status(
        json,
        warp::http::StatusCode::OK,
    )))
}

async fn warp_admin_task(s: Arc<Server>, sa: SocketAddr) -> Result<()> {
    let routes = {
        let s = Arc::clone(&s);
        warp::any().map(move || Arc::clone(&s))
            .and(warp::path!("api" / "v1" / "domains"))
            .and_then(domains)
    }.or({
        let s = Arc::clone(&s);
        warp::any().map(move || Arc::clone(&s))
            .and(warp::path!("api" / "v1" / "check" / String))
            .and_then(check_domain)
    });

    warp::serve(routes).bind(sa).await;

    Ok(())
}

async fn periodic_task(s: Arc<Server>) {
    let interval = tokio::time::Duration::from_secs(s.config.check_interval_sec);
    let mut interval = tokio::time::interval(interval);
    loop {
        if let Err(e) = check_all_records(&s).await {
            println!("Error checking records: {}", e);
        } else {
            // Save the db to disk
            let m = s.m.read().await;
            let Ok(db) = serde_yaml::to_string(&m.db) else {
                println!("Error serializing db to YAML");
                interval.tick().await;
                continue;
            };
            if let Err(e) = tokio::fs::write(&s.config.db, &db).await {
                println!("Error writing db to disk: {}", e);
            }
        }
        interval.tick().await;
    }
}

async fn async_main() -> Result<()> {
    // read bounce_pkt.yaml with tokio::fs
    let config = tokio::fs::read_to_string("./config.yaml").await?;
    let config = serde_yaml::from_str::<Config>(&config)?;

    let bind = config.bind.parse::<SocketAddr>()
        .map_err(|_| eyre!("Invalid bind address: {}", config.bind))?;
    let admin_bind = config.admin_bind.parse::<SocketAddr>()
        .map_err(|_| eyre!("Invalid admin bind address: {}", config.admin_bind))?;

    let resolver =
        hickory_resolver::TokioResolver::builder_tokio()?.build();

    // if db exists, load it, else create a new one
    let db = if tokio::fs::metadata(&config.db).await.is_ok() {
        let db_str = tokio::fs::read_to_string(&config.db).await?;
        serde_yaml::from_str::<Db>(&db_str)?
    } else {
        Db::default()
    };

    let s = Arc::new(Server {
        m: RwLock::new(ServerMut {
            db,
            bounce_mappings: HashMap::new(),
        }),
        config,
        resolver,
    });

    tokio::task::spawn(warp_task(Arc::clone(&s), bind));
    tokio::task::spawn(warp_admin_task(Arc::clone(&s), admin_bind));

    periodic_task(Arc::clone(&s)).await;

    Ok(())
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("tokio-worker")
        .thread_stack_size(32 * 1024 * 1024)
        .enable_time()
        .enable_io()
        .build()
        .unwrap();
    runtime.block_on(async_main())
}