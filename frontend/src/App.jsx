import { useEffect, useState } from "react";

async function api(url, body) {
  const r = await fetch(url, body === undefined ? undefined : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const t = await r.text();
  if (!r.ok) throw new Error(t);
  return JSON.parse(t);
}

const short = (h) => (h ? h.slice(0, 12) + "…" : "—");

function Group({ label, kind, items }) {
  if (!items.length) return null;
  return (
    <section className={`group ${kind}`}>
      <h3>{label} <span>{items.length}</span></h3>
      <ul>
        {items.map((c) => (
          <li key={c.path}>
            <b>{c.path}</b>
            <code>{short(c.old_hash)} → {short(c.new_hash)}</code>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function App() {
  const [info, setInfo] = useState(null);
  const [path, setPath] = useState("");
  const [report, setReport] = useState(null);
  const [pw, setPw] = useState("");
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);

  const refresh = () => api("/api/status").then(setInfo).catch(() => setInfo({ exists: false, offline: true }));
  useEffect(() => { refresh(); }, []);

  const run = async (fn, ok) => {
    setBusy(true); setMsg(null);
    try { const r = await fn(); if (ok) setMsg({ good: true, text: ok(r) }); await refresh(); }
    catch (e) { setMsg({ good: false, text: e.message }); }
    setBusy(false);
  };

  const create = () => run(async () => { const r = await api("/api/baseline", { path }); setReport(null); return r; },
    (r) => `Baseline saved: ${r.count} files hashed with SHA-256.`);
  const check = () => run(async () => setReport(await api("/api/check", {})));
  const accept = () => run(async () => { await api("/api/accept", {}); setReport(await api("/api/check", {})); },
    () => "Changes approved. The baseline now matches your files.");
  const encrypt = () => run(() => api("/api/encrypt", { password: pw }), () => "Encrypted copy saved as baseline.enc.");
  const verify = () => run(() => api("/api/verify-encrypted", { password: pw }),
    (r) => (r.match ? "Password works. Encrypted copy matches the plain baseline." : "Decrypted, but it differs from the plain baseline."));

  const warn = report?.status === "WARNING";
  const good = report?.status === "OK";
  const n = report ? report.added.length + report.modified.length + report.deleted.length : 0;

  return (
    <main>
      <header>
        <div className="shield" aria-hidden>◆</div>
        <div><h1>File Integrity Monitor</h1><p>SHA-256 fingerprints tell you when a file was added, edited or removed.</p></div>
      </header>

      {info?.offline && <div className="note bad">Can't reach the backend. Start it with <code>cargo run -- serve</code>.</div>}

      <div className={`banner ${warn ? "warn" : good ? "ok" : ""}`} role="status">
        {warn && <><strong>Warning: {n} unapproved change{n > 1 ? "s" : ""} found.</strong><span>Review them below. If you made them, approve to update the baseline.</span></>}
        {good && <><strong>All files verified.</strong><span>Checked {report.total} files at {report.checked_at}.</span></>}
        {!report && <><strong>{info?.exists ? "Baseline ready." : "No baseline yet."}</strong><span>{info?.exists ? `Watching ${info.root} (${info.count} files). Run a check.` : "Enter a folder path to start."}</span></>}
      </div>

      <div className="card">
        <label htmlFor="p">Folder to monitor</label>
        <div className="row">
          <input id="p" value={path} onChange={(e) => setPath(e.target.value)} placeholder="/home/you/fim-test or C:\fim-test" />
          <button className="ghost" disabled={busy || !path} onClick={create}>Create baseline</button>
          <button disabled={busy || !info?.exists} onClick={check}>Run check</button>
        </div>
        {info?.exists && <small>Current baseline: {info.root} · created {info.created}</small>}
      </div>

      {report && (
        <div className="card">
          <Group label="Added" kind="added" items={report.added} />
          <Group label="Modified" kind="modified" items={report.modified} />
          <Group label="Deleted" kind="deleted" items={report.deleted} />
          {good && <p className="muted">No differences from the baseline.</p>}
          {warn && (
            <div className="row end">
              <small>Only approve changes you made yourself.</small>
              <button disabled={busy} onClick={accept}>Approve and update baseline</button>
            </div>
          )}
        </div>
      )}

      <div className="card">
        <label htmlFor="w">Encrypted baseline copy</label>
        <div className="row">
          <input id="w" type="password" autoComplete="off" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="Password (8+ characters)" />
          <button className="ghost" disabled={busy || !info?.exists || !pw} onClick={encrypt}>Encrypt</button>
          <button className="ghost" disabled={busy || !info?.encrypted || !pw} onClick={verify}>Verify</button>
        </div>
        <small>The password is never stored. Keep it away from the encrypted file.</small>
      </div>

      {msg && <div className={`note ${msg.good ? "ok" : "bad"}`}>{msg.text}</div>}
    </main>
  );
}
