//! FIM: File Integrity Monitor (SHA-256 baseline, ADDED/MODIFIED/DELETED, encrypted copy, API for React UI)
use anyhow::{bail, Context, Result};
use argon2::Argon2;
use axum::{http::StatusCode, routing::{get, post}, Json, Router};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::{self, Read, Write}, path::Path};
use tower_http::cors::CorsLayer;
use walkdir::WalkDir;

const BASELINE: &str = "baseline.json"; // plain-text copy
const ENCRYPTED: &str = "baseline.enc"; // encrypted copy

#[derive(Serialize, Deserialize, Clone)]
struct Baseline { root: String, created: String, files: BTreeMap<String, String> }

#[derive(Serialize)]
struct Change { path: String, old_hash: Option<String>, new_hash: Option<String> }

#[derive(Serialize)]
struct Report {
    status: &'static str, // "OK" or "WARNING"
    root: String, checked_at: String, total: usize,
    added: Vec<Change>, modified: Vec<Change>, deleted: Vec<Change>,
}

fn now() -> String { chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string() }

fn hash_file(p: &Path) -> Result<String> {
    let mut f = fs::File::open(p).with_context(|| format!("cannot open {}", p.display()))?;
    let (mut h, mut buf) = (Sha256::new(), [0u8; 65536]);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn scan(root: &Path) -> Result<BTreeMap<String, String>> {
    if !root.is_dir() { bail!("'{}' is not a folder", root.display()); }
    let mut m = BTreeMap::new();
    for e in WalkDir::new(root).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
        let rel = e.path().strip_prefix(root)?.to_string_lossy().replace('\\', "/");
        if rel == BASELINE || rel == ENCRYPTED { continue; }
        m.insert(rel, hash_file(e.path())?);
    }
    Ok(m)
}

fn create_baseline(path: &str) -> Result<Baseline> {
    let root = fs::canonicalize(path).with_context(|| format!("path not found: {path}"))?;
    let b = Baseline { root: root.to_string_lossy().into(), created: now(), files: scan(&root)? };
    fs::write(BASELINE, serde_json::to_string_pretty(&b)?)?;
    Ok(b)
}

fn load() -> Result<Baseline> {
    let s = fs::read_to_string(BASELINE).context("no baseline yet: create one first")?;
    Ok(serde_json::from_str(&s)?)
}

fn check() -> Result<Report> {
    let b = load()?;
    let cur = scan(Path::new(&b.root))?;
    let (mut added, mut modified, mut deleted) = (vec![], vec![], vec![]);
    for (p, h) in &cur {
        match b.files.get(p) {
            None => added.push(Change { path: p.clone(), old_hash: None, new_hash: Some(h.clone()) }),
            Some(old) if old != h => modified.push(Change { path: p.clone(), old_hash: Some(old.clone()), new_hash: Some(h.clone()) }),
            _ => {}
        }
    }
    for (p, h) in &b.files {
        if !cur.contains_key(p) { deleted.push(Change { path: p.clone(), old_hash: Some(h.clone()), new_hash: None }); }
    }
    let ok = added.is_empty() && modified.is_empty() && deleted.is_empty();
    Ok(Report { status: if ok { "OK" } else { "WARNING" }, root: b.root, checked_at: now(), total: cur.len(), added, modified, deleted })
}

// --- encryption: Argon2 (password -> key) + ChaCha20-Poly1305. File = salt(16) | nonce(12) | ciphertext
fn derive(pw: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut k = [0u8; 32];
    Argon2::default().hash_password_into(pw.as_bytes(), salt, &mut k).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(k)
}

fn encrypt_baseline(pw: &str) -> Result<()> {
    let data = fs::read(BASELINE).context("no baseline yet")?;
    let (mut salt, mut nonce) = ([0u8; 16], [0u8; 12]);
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = derive(pw, &salt)?;
    let ct = ChaCha20Poly1305::new(Key::from_slice(&key)).encrypt(Nonce::from_slice(&nonce), data.as_ref())
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    fs::write(ENCRYPTED, [&salt[..], &nonce[..], &ct].concat())?;
    Ok(())
}

fn decrypt_baseline(pw: &str) -> Result<Vec<u8>> {
    let d = fs::read(ENCRYPTED).context("no encrypted baseline yet")?;
    if d.len() < 28 { bail!("encrypted file is corrupt"); }
    let key = derive(pw, &d[..16])?;
    ChaCha20Poly1305::new(Key::from_slice(&key)).decrypt(Nonce::from_slice(&d[16..28]), &d[28..])
        .map_err(|_| anyhow::anyhow!("wrong password or file was tampered with"))
}

fn verify_encrypted(pw: &str) -> Result<bool> { Ok(decrypt_baseline(pw)? == fs::read(BASELINE)?) }

// --- CLI helpers
fn ask(q: &str) -> String {
    print!("{q}"); io::stdout().flush().ok();
    let mut s = String::new(); io::stdin().read_line(&mut s).ok();
    s.trim().trim_matches('"').to_string()
}

fn print_report(r: &Report) {
    println!("Checked at {} | folder: {} | files: {}", r.checked_at, r.root, r.total);
    for (tag, v) in [("ADDED", &r.added), ("MODIFIED", &r.modified), ("DELETED", &r.deleted)] {
        for c in v { println!("[{tag}] {}", c.path); }
    }
    if r.status == "OK" { println!("OK: all files match the baseline."); }
    else { println!("WARNING: integrity check failed ({} change(s)).", r.added.len() + r.modified.len() + r.deleted.len()); }
}

// --- HTTP API (used by the React frontend)
type Api<T> = Result<Json<T>, (StatusCode, String)>;
fn bad(e: anyhow::Error) -> (StatusCode, String) { (StatusCode::BAD_REQUEST, format!("{e:#}")) }
#[derive(Deserialize)] struct PathIn { path: String }
#[derive(Deserialize)] struct PwIn { password: String }

async fn status() -> Json<serde_json::Value> {
    match load() {
        Ok(b) => Json(serde_json::json!({"exists": true, "root": b.root, "created": b.created, "count": b.files.len(), "encrypted": Path::new(ENCRYPTED).exists()})),
        Err(_) => Json(serde_json::json!({"exists": false})),
    }
}
async fn api_create(Json(i): Json<PathIn>) -> Api<serde_json::Value> {
    let b = create_baseline(&i.path).map_err(bad)?;
    Ok(Json(serde_json::json!({"root": b.root, "count": b.files.len()})))
}
async fn api_check() -> Api<Report> { check().map(Json).map_err(bad) }
async fn api_accept() -> Api<serde_json::Value> { // user approves changes: baseline updated
    let b = load().map_err(bad)?;
    let n = create_baseline(&b.root).map_err(bad)?;
    Ok(Json(serde_json::json!({"count": n.files.len()})))
}
async fn api_encrypt(Json(i): Json<PwIn>) -> Api<serde_json::Value> {
    if i.password.len() < 8 { return Err(bad(anyhow::anyhow!("use a password of 8+ characters"))); }
    encrypt_baseline(&i.password).map_err(bad)?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn api_verify(Json(i): Json<PwIn>) -> Api<serde_json::Value> {
    Ok(Json(serde_json::json!({"match": verify_encrypted(&i.password).map_err(bad)?})))
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(|s| s.as_str()) {
        Some("init") => {
            let p = a.get(1).cloned().unwrap_or_else(|| ask("Folder to monitor: "));
            let b = create_baseline(&p)?;
            println!("[{}] Baseline saved to {BASELINE}: {} files, SHA-256", b.created, b.files.len());
            for (f, h) in &b.files { println!("{h}  {f}"); }
        }
        Some("check") => { let r = check()?; print_report(&r); if r.status != "OK" { std::process::exit(1); } }
        Some("accept") => { let b = load()?; let n = create_baseline(&b.root)?; println!("Baseline updated ({} files).", n.files.len()); }
        Some("encrypt") => { encrypt_baseline(&rpassword::prompt_password("Password: ")?)?; println!("Saved {ENCRYPTED}"); }
        Some("verify-enc") => {
            let ok = verify_encrypted(&rpassword::prompt_password("Password: ")?)?;
            println!("{}", if ok { "Decryption OK: matches plain baseline." } else { "Decrypted, but differs from plain baseline!" });
        }
        Some("serve") => {
            let app = Router::new()
                .route("/api/status", get(status)).route("/api/baseline", post(api_create))
                .route("/api/check", post(api_check)).route("/api/accept", post(api_accept))
                .route("/api/encrypt", post(api_encrypt)).route("/api/verify-encrypted", post(api_verify))
                .layer(CorsLayer::permissive());
            let l = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
            println!("FIM API on http://127.0.0.1:8080 (local only)");
            axum::serve(l, app).await?;
        }
        _ => println!("Usage: fim <init [path] | check | accept | encrypt | verify-enc | serve>"),
    }
    Ok(())
}
