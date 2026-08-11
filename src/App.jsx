import { useState, useRef, useCallback, useEffect } from "react";

// ── Design tokens ────────────────────────────────────────────────────────────
// Palette: cool slate base, single teal accent, crisp reds for blocked state
// Signature: the scanner animation in gateway check sequence

const C = {
  slate50:  "#f8fafc",
  slate100: "#f1f5f9",
  slate200: "#e2e8f0",
  slate300: "#cbd5e1",
  slate400: "#94a3b8",
  slate500: "#64748b",
  slate600: "#475569",
  slate700: "#334155",
  slate800: "#1e293b",
  slate900: "#0f172a",
  teal500:  "#14b8a6",
  teal600:  "#0d9488",
  teal50:   "#f0fdfa",
  teal100:  "#ccfbf1",
  red500:   "#ef4444",
  red50:    "#fef2f2",
  red100:   "#fee2e2",
  amber500: "#f59e0b",
  amber50:  "#fffbeb",
};

// ── Tiny helpers ─────────────────────────────────────────────────────────────
const truncHash = (h) => h ? `${h.slice(0,8)}…${h.slice(-4)}` : "—";

const Badge = ({ color = "slate", children }) => {
  const map = {
    teal:  "background:#ccfbf1;color:#0d9488;border:1px solid #99f6e4",
    red:   "background:#fee2e2;color:#dc2626;border:1px solid #fca5a5",
    amber: "background:#fffbeb;color:#d97706;border:1px solid #fde68a",
    slate: "background:#f1f5f9;color:#475569;border:1px solid #e2e8f0",
  };
  return (
    <span style={{
      display:"inline-flex",alignItems:"center",gap:4,
      padding:"2px 8px",borderRadius:99,fontSize:11,fontWeight:600,
      letterSpacing:"0.03em",...Object.fromEntries(
        map[color].split(";").map(s=>s.split(":"))
      )
    }}>{children}</span>
  );
};

const Mono = ({ children, dim }) => (
  <span style={{
    fontFamily:"'JetBrains Mono',ui-monospace,monospace",
    fontSize:12,color:dim?C.slate400:C.slate700,letterSpacing:"-0.01em"
  }}>{children}</span>
);

const Divider = () => (
  <div style={{height:1,background:C.slate200,margin:"20px 0"}} />
);

// ── File Drop Zone ────────────────────────────────────────────────────────────
function DropZone({ label, onFile, accept = "image/*", file }) {
  const ref = useRef();
  const [over, setOver] = useState(false);

  const handle = (f) => {
    if (!f) return;
    const url = URL.createObjectURL(f);
    onFile({ file: f, url, name: f.name, size: f.size });
  };

  return (
    <div
      onClick={() => ref.current.click()}
      onDragOver={e => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={e => { e.preventDefault(); setOver(false); handle(e.dataTransfer.files[0]); }}
      style={{
        border: `2px dashed ${over ? C.teal500 : C.slate300}`,
        borderRadius: 10,
        padding: "28px 20px",
        textAlign: "center",
        cursor: "pointer",
        background: over ? C.teal50 : C.slate50,
        transition: "all 0.15s",
        userSelect: "none",
      }}
    >
      <input ref={ref} type="file" accept={accept} style={{display:"none"}}
        onChange={e => handle(e.target.files[0])} />
      {file ? (
        <div style={{display:"flex",alignItems:"center",gap:12,justifyContent:"center"}}>
          <img src={file.url} alt="" style={{width:64,height:64,objectFit:"cover",borderRadius:6,border:`1px solid ${C.slate200}`}} />
          <div style={{textAlign:"left"}}>
            <div style={{fontWeight:600,fontSize:13,color:C.slate800}}>{file.name}</div>
            <div style={{fontSize:11,color:C.slate400,marginTop:2}}>
              {(file.size/1024).toFixed(1)} KB · click to change
            </div>
          </div>
        </div>
      ) : (
        <>
          <div style={{fontSize:28,marginBottom:8}}>📁</div>
          <div style={{fontWeight:600,color:C.slate700,fontSize:13}}>{label}</div>
          <div style={{fontSize:12,color:C.slate400,marginTop:4}}>
            drag & drop or click to browse
          </div>
        </>
      )}
    </div>
  );
}

// ── Check row (gateway scanner) ───────────────────────────────────────────────
function CheckRow({ n, label, state, detail, value }) {
  // state: "idle" | "running" | "pass" | "fail" | "skip"
  const iconMap = {
    idle:    { ch: "○", color: C.slate300 },
    running: { ch: "◐", color: C.amber500, spin: true },
    pass:    { ch: "✓", color: C.teal600 },
    fail:    { ch: "✗", color: C.red500 },
    skip:    { ch: "—", color: C.slate300 },
  };
  const ic = iconMap[state] || iconMap.idle;

  return (
    <div style={{
      display:"grid",
      gridTemplateColumns:"20px 1fr auto",
      gap:"0 12px",
      padding:"10px 0",
      borderBottom:`1px solid ${C.slate100}`,
      alignItems:"start"
    }}>
      <span style={{
        fontSize:14,fontWeight:700,color:ic.color,
        animation:ic.spin?"spin 1s linear infinite":undefined,
        display:"inline-block",lineHeight:1,paddingTop:1
      }}>{ic.ch}</span>
      <div>
        <div style={{fontSize:12,fontWeight:600,color:C.slate700,lineHeight:1.4}}>
          <span style={{color:C.slate400,marginRight:6,fontFamily:"monospace"}}>
            Check {n}
          </span>
          {label}
        </div>
        {detail && (
          <div style={{fontSize:11,color:state==="fail"?C.red500:C.slate400,marginTop:3,lineHeight:1.5}}>
            {detail}
          </div>
        )}
      </div>
      {value !== undefined && (
        <div style={{textAlign:"right",flexShrink:0}}>
          <Mono>{value}</Mono>
        </div>
      )}
    </div>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────
function Stat({ label, value, sub, accent }) {
  return (
    <div style={{
      background:C.slate50,border:`1px solid ${C.slate200}`,
      borderRadius:8,padding:"12px 14px"
    }}>
      <div style={{fontSize:11,color:C.slate400,fontWeight:600,letterSpacing:"0.05em",
        textTransform:"uppercase",marginBottom:4}}>{label}</div>
      <div style={{fontSize:20,fontWeight:700,color:accent||C.slate800,lineHeight:1}}>
        {value}
      </div>
      {sub && <div style={{fontSize:11,color:C.slate400,marginTop:4}}>{sub}</div>}
    </div>
  );
}

// ── Registration panel ────────────────────────────────────────────────────────
function RegisterPanel() {
  const [file, setFile] = useState(null);
  const [step, setStep] = useState("idle"); // idle|running|done|error
  const [result, setResult] = useState(null);
  const [log, setLog] = useState([]);

  const addLog = (msg) => setLog(prev => [...prev, msg]);

  const simulate = async () => {
    if (!file) return;
    setStep("running"); setLog([]); setResult(null);

    const steps = [
      [600,  "Phase 1 — YOLO ROI masking: detecting foreground objects …"],
      [1200, "Phase 1 — Background mask M_buffer generated (erosion ×3 applied)"],
      [600,  "Phase 2 — Bilateral filter + Gaussian blur applied (texture removed)"],
      [800,  "Phase 2 — DWT ×3 (Haar) → LL3 subband extracted (1/64 resolution)"],
      [600,  "Phase 3 — 4×4 DCT blockwise on LL3, DC coefficients collected"],
      [700,  "Phase 4 — Dark pool (15%) + Bright pool (15%) identified"],
      [900,  "Phase 5 — 5-replica CSPRNG anchor selection (SHA-256 derived seeds)"],
      [600,  "Phase 5 — Majority vote (3/5) → 256-bit W_key generated  ✓"],
      [500,  "Embedding scattered LSB tamper seal (MASTER_SEED positions) …"],
      [600,  "AES-256-GCM encrypting original → image_vault/  ✓"],
      [400,  "HMAC-SHA256 signing ledger record …"],
      [500,  "Saving to MongoDB Atlas (ledger collection) …  ✓"],
    ];

    for (const [delay, msg] of steps) {
      await new Promise(r => setTimeout(r, delay));
      addLog(msg);
    }

    const fakeKey = Array.from({length:32},()=>Math.round(Math.random())).join("");
    const fakeHash = [...Array(40)].map(()=>"0123456789abcdef"[Math.floor(Math.random()*16)]).join("");

    setResult({
      filename: file.name,
      signedName: file.name.replace(/\.[^.]+$/, "_signed.png"),
      keyBalance: 49.6,
      keyBits: fakeKey,
      tamperHash: fakeHash,
      vaultFile: `image_vault/${file.name.replace(/\.[^.]+$/,"")}`,
      timestamp: new Date().toLocaleString(),
    });
    setStep("done");
  };

  return (
    <div style={{display:"flex",flexDirection:"column",gap:20}}>
      <div>
        <div style={{fontSize:13,fontWeight:600,color:C.slate700,marginBottom:8}}>
          Original image
        </div>
        <DropZone label="Upload the original image to register" onFile={setFile} file={file} />
      </div>

      {file && step === "idle" && (
        <button
          onClick={simulate}
          style={{
            background:C.teal600,color:"#fff",border:"none",borderRadius:8,
            padding:"11px 20px",fontWeight:600,fontSize:13,cursor:"pointer",
            letterSpacing:"0.01em"
          }}
        >
          Register image
        </button>
      )}

      {step === "running" && (
        <div style={{
          background:C.slate50,border:`1px solid ${C.slate200}`,
          borderRadius:8,padding:14
        }}>
          <div style={{fontSize:11,fontWeight:700,color:C.slate500,
            letterSpacing:"0.06em",textTransform:"uppercase",marginBottom:10}}>
            Pipeline
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:4,maxHeight:260,overflowY:"auto"}}>
            {log.map((l,i)=>(
              <div key={i} style={{
                fontSize:11.5,color:l.includes("✓")?C.teal600:C.slate500,
                fontFamily:l.startsWith("Phase")||l.startsWith("AES")||l.startsWith("HMAC")||l.startsWith("Saving")||l.startsWith("Embed")?"inherit":"monospace",
                lineHeight:1.6,display:"flex",gap:8,alignItems:"baseline"
              }}>
                <span style={{color:C.slate300,flexShrink:0}}>{String(i+1).padStart(2,"0")}</span>
                {l}
              </div>
            ))}
            <div style={{display:"flex",gap:6,alignItems:"center",color:C.amber500,fontSize:11.5,marginTop:4}}>
              <span style={{animation:"spin 1s linear infinite",display:"inline-block"}}>◐</span>
              Processing…
            </div>
          </div>
        </div>
      )}

      {step === "done" && result && (
        <div style={{display:"flex",flexDirection:"column",gap:16}}>
          <div style={{
            background:C.teal50,border:`1px solid #99f6e4`,borderRadius:8,
            padding:"12px 14px",display:"flex",gap:10,alignItems:"flex-start"
          }}>
            <span style={{fontSize:18}}>✅</span>
            <div>
              <div style={{fontWeight:700,color:C.teal600,fontSize:13}}>
                Registration complete
              </div>
              <div style={{fontSize:12,color:C.slate500,marginTop:2}}>
                Signed copy ready for distribution. Original encrypted in vault.
              </div>
            </div>
          </div>

          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
            <Stat label="Key balance" value={`${result.keyBalance}%`}
              sub="ideal ≈ 50%" accent={C.teal600} />
            <Stat label="Key length" value="256 bits" sub="5-replica majority vote" />
            <Stat label="Signed copy" value={result.signedName}
              sub="distribute this" />
            <Stat label="Registered" value={result.timestamp} />
          </div>

          <div style={{background:C.slate50,border:`1px solid ${C.slate200}`,
            borderRadius:8,padding:14}}>
            <div style={{fontSize:11,fontWeight:700,color:C.slate400,
              letterSpacing:"0.06em",textTransform:"uppercase",marginBottom:10}}>
              Cryptographic record
            </div>
            {[
              ["Tamper hash", truncHash(result.tamperHash)],
              ["Vault file", result.vaultFile + ".enc"],
              ["Ledger", "MongoDB Atlas · ledger collection"],
              ["Seal", "AES-256-GCM + HMAC-SHA256"],
            ].map(([k,v])=>(
              <div key={k} style={{display:"flex",justifyContent:"space-between",
                padding:"6px 0",borderBottom:`1px solid ${C.slate100}`,fontSize:12}}>
                <span style={{color:C.slate500}}>{k}</span>
                <Mono>{v}</Mono>
              </div>
            ))}
          </div>

          <div style={{
            background:"#fffbeb",border:"1px solid #fde68a",borderRadius:8,
            padding:"10px 14px",fontSize:12,color:"#92400e"
          }}>
            ⚠️ Send only the <strong>signed copy</strong> to the recipient.
            The original is AES-256-GCM encrypted in the vault.
          </div>

          <button onClick={()=>{setStep("idle");setFile(null);setLog([]);setResult(null);}}
            style={{
              background:"white",color:C.slate700,border:`1px solid ${C.slate300}`,
              borderRadius:8,padding:"10px 20px",fontWeight:600,fontSize:13,
              cursor:"pointer"
            }}>
            Register another image
          </button>
        </div>
      )}
    </div>
  );
}

// ── Gateway panel ─────────────────────────────────────────────────────────────
function GatewayPanel() {
  const [file, setFile] = useState(null);
  const [platform, setPlatform] = useState("police_portal");
  const [step, setStep] = useState("idle");
  const [checks, setChecks] = useState({
    pre:  { state:"idle" },
    c1:   { state:"idle" },
    c2:   { state:"idle" },
    c3:   { state:"idle" },
  });
  const [result, setResult] = useState(null);
  const [showRecover, setShowRecover] = useState(false);
  const [recovered, setRecovered] = useState(false);

  const PLAT = {
    social_media:  { label:"SecureShare · Social Media",  threshold:0.75 },
    news_agency:   { label:"TruthWire · News Agency",     threshold:0.80 },
    police_portal: { label:"CrimeVault · Police Portal",  threshold:0.85 },
  };

  const setCheck = (key, val) =>
    setChecks(prev => ({ ...prev, [key]: { ...prev[key], ...val } }));

  const delay = ms => new Promise(r => setTimeout(r, ms));

  const simulate = async () => {
    if (!file) return;
    setStep("running");
    setResult(null);
    setShowRecover(false);
    setRecovered(false);
    setChecks({ pre:{state:"idle"}, c1:{state:"idle"}, c2:{state:"idle"}, c3:{state:"idle"} });

    const isTampered = file.name.toLowerCase().includes("ai") ||
                       file.name.toLowerCase().includes("tamper") ||
                       file.name.toLowerCase().includes("fake");

    // Pre-check
    setCheck("pre", { state:"running" });
    await delay(900);
    setCheck("pre", { state:"pass", detail:"Not in blacklist — first time seen" });

    // Check 1
    await delay(300);
    setCheck("c1", { state:"running" });
    await delay(1100);
    if (isTampered) {
      setCheck("c1", { state:"fail", detail:"SHA-256 hash mismatch — LSB seal destroyed. AI pixel regeneration detected." });
    } else {
      setCheck("c1", { state:"pass", detail:"LSB seal intact — SHA-256 matches registered hash" });
    }

    // Check 2
    await delay(300);
    if (isTampered) {
      setCheck("c2", { state:"running" });
      await delay(1400);
      setCheck("c2", { state:"fail", detail:"38/256 cells flagged (MAD > 5.0). Tampered region: upper-right quadrant." });
    } else {
      setCheck("c2", { state:"skip", detail:"Skipped — tamper seal intact" });
    }

    // Check 3
    await delay(300);
    setCheck("c3", { state:"running" });
    await delay(1200);
    const nc = isTampered ? 0.6142 : 0.9531;
    const threshold = PLAT[platform].threshold;
    const ncPass = nc >= threshold;
    setCheck("c3", {
      state: ncPass ? "pass" : "fail",
      detail: ncPass
        ? `NC = ${nc} ≥ ${threshold} · ownership proven`
        : `NC = ${nc} < ${threshold} · structural fingerprint degraded`,
      value: nc.toFixed(4),
    });

    await delay(400);

    const decision = isTampered ? "BLOCK" : "ALLOW";
    setResult({
      decision,
      filename: file.name,
      nc,
      ncPass,
      bitAcc: isTampered ? 73.4 : 97.7,
      matchedTo: "142025.png",
      registeredAt: "2026-06-22 10:11:26",
      tamperCells: isTampered ? 38 : 0,
      checkTime: (2.8 + Math.random()*0.4).toFixed(1),
    });

    if (decision === "BLOCK") setShowRecover(true);
    setStep("done");
  };

  return (
    <div style={{display:"flex",flexDirection:"column",gap:20}}>
      <div>
        <div style={{fontSize:13,fontWeight:600,color:C.slate700,marginBottom:8}}>
          Platform
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
          {Object.entries(PLAT).map(([key,p])=>(
            <button key={key} onClick={()=>setPlatform(key)}
              style={{
                padding:"10px 8px",borderRadius:7,fontSize:11.5,fontWeight:600,
                border:`1.5px solid ${platform===key?C.teal500:C.slate200}`,
                background:platform===key?C.teal50:"white",
                color:platform===key?C.teal600:C.slate600,
                cursor:"pointer",lineHeight:1.4,textAlign:"center"
              }}>
              {p.label.split(" · ").map((l,i)=>(
                <div key={i} style={{fontWeight:i===0?700:400}}>{l}</div>
              ))}
              <div style={{fontSize:10,color:C.slate400,marginTop:2,fontWeight:400}}>
                NC ≥ {p.threshold}
              </div>
            </button>
          ))}
        </div>
      </div>

      <div>
        <div style={{fontSize:13,fontWeight:600,color:C.slate700,marginBottom:8}}>
          Image to verify
        </div>
        <DropZone
          label="Upload image to check"
          onFile={f => { setFile(f); setStep("idle"); setResult(null); }}
          file={file}
        />
      </div>

      {file && step === "idle" && (
        <button onClick={simulate} style={{
          background:C.slate800,color:"#fff",border:"none",borderRadius:8,
          padding:"11px 20px",fontWeight:600,fontSize:13,cursor:"pointer"
        }}>
          Run gateway check
        </button>
      )}

      {(step === "running" || step === "done") && (
        <div style={{
          background:C.slate50,border:`1px solid ${C.slate200}`,
          borderRadius:8,padding:14
        }}>
          <div style={{fontSize:11,fontWeight:700,color:C.slate400,
            letterSpacing:"0.06em",textTransform:"uppercase",marginBottom:10}}>
            Verification checks
          </div>
          <CheckRow n="0" label="Dual-hash blacklist (SHA-256 + pHash)"
            state={checks.pre.state} detail={checks.pre.detail} />
          <CheckRow n="1" label="Scattered LSB tamper seal"
            state={checks.c1.state} detail={checks.c1.detail} />
          <CheckRow n="2" label={`MAD localisation (16×16 grid, floor ${5.0})`}
            state={checks.c2.state} detail={checks.c2.detail} />
          <CheckRow n="3" label="Zero-watermark NC score"
            state={checks.c3.state} detail={checks.c3.detail}
            value={checks.c3.value} />
        </div>
      )}

      {step === "done" && result && (
        <>
          <div style={{
            background: result.decision==="ALLOW" ? C.teal50 : C.red50,
            border:`1.5px solid ${result.decision==="ALLOW"?"#99f6e4":"#fca5a5"}`,
            borderRadius:10,padding:"16px 18px"
          }}>
            <div style={{
              fontSize:16,fontWeight:800,
              color:result.decision==="ALLOW"?C.teal600:C.red500,
              letterSpacing:"-0.01em",marginBottom:8
            }}>
              {result.decision==="ALLOW"?"✅  Upload allowed":"🚫  Upload blocked"}
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
              <Stat label="NC Score" value={result.nc.toFixed(4)}
                accent={result.ncPass?C.teal600:C.red500}
                sub={`threshold ${PLAT[platform].threshold}`} />
              <Stat label="Bit accuracy" value={`${result.bitAcc}%`}
                sub="≥87.5% expected" />
              <Stat label="Matched to" value={result.matchedTo}
                sub={`registered ${result.registeredAt}`} />
              <Stat label="Check time" value={`${result.checkTime}s`}
                sub={result.tamperCells>0?`${result.tamperCells}/256 cells tampered`:"No tampered cells"} />
            </div>
          </div>

          {result.decision==="BLOCK" && showRecover && !recovered && (
            <div style={{
              background:"white",border:`1px solid ${C.slate200}`,borderRadius:8,padding:16
            }}>
              <div style={{fontWeight:700,color:C.slate800,fontSize:13,marginBottom:6}}>
                🔓 Recover original
              </div>
              <div style={{fontSize:12,color:C.slate500,marginBottom:12,lineHeight:1.6}}>
                The verified original is safely stored in the AES-256-GCM vault.
                Delivering it will embed a fresh tamper seal and log the delivery —
                activating post-delivery tamper lock.
              </div>
              <div style={{display:"flex",gap:8}}>
                <button onClick={()=>setRecovered(true)} style={{
                  background:C.teal600,color:"#fff",border:"none",borderRadius:7,
                  padding:"9px 16px",fontWeight:600,fontSize:12,cursor:"pointer"
                }}>
                  Decrypt &amp; deliver original
                </button>
                <button onClick={()=>setShowRecover(false)} style={{
                  background:"white",color:C.slate600,border:`1px solid ${C.slate300}`,
                  borderRadius:7,padding:"9px 16px",fontWeight:600,fontSize:12,cursor:"pointer"
                }}>
                  Skip
                </button>
              </div>
            </div>
          )}

          {recovered && (
            <div style={{
              background:C.teal50,border:`1px solid #99f6e4`,borderRadius:8,
              padding:"12px 14px"
            }}>
              <div style={{fontWeight:700,color:C.teal600,fontSize:13,marginBottom:4}}>
                ✅ Original recovered and delivered
              </div>
              <div style={{fontSize:12,color:C.slate500,lineHeight:1.6}}>
                <div>• <Mono>recovered_{result.filename.replace(/\.[^.]+$/,"")+".png"}</Mono> saved</div>
                <div>• Fresh LSB seal embedded on delivered copy</div>
                <div>• Delivery logged — post-delivery tamper lock active</div>
                <div>• Any future edit of this file will be caught and blocked</div>
              </div>
            </div>
          )}

          <button onClick={()=>{setStep("idle");setFile(null);setResult(null);}}
            style={{
              background:"white",color:C.slate700,border:`1px solid ${C.slate300}`,
              borderRadius:8,padding:"10px 20px",fontWeight:600,fontSize:13,cursor:"pointer"
            }}>
            Check another image
          </button>
        </>
      )}
    </div>
  );
}

// ── Results panel ─────────────────────────────────────────────────────────────
const MOCK_RESULTS = [
  { filename:"142025_ai.png",   decision:"BLOCK", nc:0.6142, bit_accuracy:73.4, tamper_status:"❌ TAMPERED", check_time_s:34.1, timestamp:"2026-06-27 16:59" },
  { filename:"142025.png",      decision:"ALLOW", nc:0.9531, bit_accuracy:97.7, tamper_status:"✅ UNTAMPERED", check_time_s:28.4, timestamp:"2026-06-27 16:45" },
  { filename:"cam3_ai.png",     decision:"BLOCK", nc:0.5891, bit_accuracy:69.1, tamper_status:"❌ TAMPERED", check_time_s:31.8, timestamp:"2026-06-27 15:22" },
  { filename:"cam3_orig.png",   decision:"ALLOW", nc:0.9609, bit_accuracy:98.0, tamper_status:"✅ UNTAMPERED", check_time_s:26.2, timestamp:"2026-06-27 15:10" },
  { filename:"312839_ai.png",   decision:"BLOCK", nc:0.0,    bit_accuracy:0.0,  tamper_status:"⛔ BLACKLISTED", check_time_s:0.3, timestamp:"2026-06-27 14:01" },
];

function ResultsPanel() {
  const blocked = MOCK_RESULTS.filter(r=>r.decision==="BLOCK").length;
  const allowed = MOCK_RESULTS.filter(r=>r.decision==="ALLOW").length;
  const avgNc   = (MOCK_RESULTS.filter(r=>r.nc>0).reduce((a,r)=>a+r.nc,0)/
                   MOCK_RESULTS.filter(r=>r.nc>0).length).toFixed(4);

  return (
    <div style={{display:"flex",flexDirection:"column",gap:20}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        <Stat label="Total runs"   value={MOCK_RESULTS.length} />
        <Stat label="Blocked"      value={blocked}  accent={C.red500}  sub={`${Math.round(blocked/MOCK_RESULTS.length*100)}%`} />
        <Stat label="Allowed"      value={allowed}  accent={C.teal600} sub={`${Math.round(allowed/MOCK_RESULTS.length*100)}%`} />
        <Stat label="Avg NC score" value={avgNc} />
      </div>

      <div style={{
        background:C.slate50,border:`1px solid ${C.slate200}`,
        borderRadius:8,overflow:"hidden"
      }}>
        <div style={{
          display:"grid",
          gridTemplateColumns:"1fr 90px 80px 80px 90px 110px",
          gap:0,
          padding:"8px 14px",
          background:C.slate100,
          borderBottom:`1px solid ${C.slate200}`
        }}>
          {["Filename","Decision","NC Score","Bit Acc.","Status","Time"].map(h=>(
            <div key={h} style={{fontSize:10.5,fontWeight:700,color:C.slate500,
              letterSpacing:"0.05em",textTransform:"uppercase"}}>{h}</div>
          ))}
        </div>
        {MOCK_RESULTS.map((r,i)=>(
          <div key={i} style={{
            display:"grid",
            gridTemplateColumns:"1fr 90px 80px 80px 90px 110px",
            padding:"10px 14px",
            borderBottom: i<MOCK_RESULTS.length-1?`1px solid ${C.slate100}`:"none",
            alignItems:"center",
            background:i%2===0?"white":C.slate50,
          }}>
            <div style={{fontSize:12,color:C.slate800,fontWeight:500,
              overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
              {r.filename}
            </div>
            <div>
              <Badge color={r.decision==="ALLOW"?"teal":"red"}>
                {r.decision}
              </Badge>
            </div>
            <div>
              <Mono dim={r.nc===0}>{r.nc===0?"—":r.nc.toFixed(4)}</Mono>
            </div>
            <div>
              <Mono dim={r.bit_accuracy===0}>
                {r.bit_accuracy===0?"—":r.bit_accuracy.toFixed(1)+"%"}
              </Mono>
            </div>
            <div style={{fontSize:11,color:C.slate500}}>{r.tamper_status}</div>
            <div style={{fontSize:11,color:C.slate400}}>{r.check_time_s}s · {r.timestamp}</div>
          </div>
        ))}
      </div>

      <div style={{
        background:"white",border:`1px solid ${C.slate200}`,
        borderRadius:8,padding:"12px 14px",
        display:"flex",gap:12,alignItems:"center"
      }}>
        <span style={{fontSize:16}}>📥</span>
        <div style={{flex:1}}>
          <div style={{fontSize:12,fontWeight:600,color:C.slate700}}>
            Sync from MongoDB Atlas
          </div>
          <div style={{fontSize:11,color:C.slate400,marginTop:1}}>
            gateway_results collection · {MOCK_RESULTS.length} records loaded
          </div>
        </div>
        <button style={{
          background:C.slate100,color:C.slate700,border:`1px solid ${C.slate200}`,
          borderRadius:6,padding:"7px 14px",fontWeight:600,fontSize:12,cursor:"pointer"
        }}>
          Refresh
        </button>
      </div>
    </div>
  );
}

// ── Main app ──────────────────────────────────────────────────────────────────
const TABS = [
  { id:"register", label:"Register", icon:"🔑" },
  { id:"gateway",  label:"Gateway",  icon:"🚦" },
  { id:"results",  label:"Results",  icon:"📊" },
];

export default function App() {
  const [tab, setTab] = useState("register");

  return (
    <div style={{
      fontFamily:"Inter,ui-sans-serif,system-ui,sans-serif",
      background:"#f8fafc",minHeight:"100vh",
      WebkitFontSmoothing:"antialiased",
    }}>
      <style>{`
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #f1f5f9; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
      `}</style>

      {/* Header */}
      <div style={{
        background:"white",borderBottom:`1px solid ${C.slate200}`,
        padding:"0 24px",position:"sticky",top:0,zIndex:100
      }}>
        <div style={{
          maxWidth:"min(880px, 94vw)",margin:"0 auto",
          display:"flex",alignItems:"center",gap:0,height:56
        }}>
          <div style={{
            display:"flex",alignItems:"center",gap:10,marginRight:"auto"
          }}>
            <div style={{
              width:32,height:32,borderRadius:7,
              background:C.teal600,display:"flex",alignItems:"center",
              justifyContent:"center",fontSize:16
            }}>🔏</div>
            <div>
              <div style={{fontSize:14,fontWeight:700,color:C.slate900,lineHeight:1.1}}>
                Zero-Watermark
              </div>
              <div style={{fontSize:10.5,color:C.slate400,lineHeight:1}}>
                Image Authentication System
              </div>
            </div>
          </div>

          <div style={{display:"flex",gap:2}}>
            {TABS.map(t=>(
              <button key={t.id} onClick={()=>setTab(t.id)} style={{
                padding:"7px 14px",borderRadius:6,border:"none",
                background:tab===t.id?C.slate100:"transparent",
                color:tab===t.id?C.slate900:C.slate500,
                fontWeight:tab===t.id?600:400,
                fontSize:13,cursor:"pointer",
                display:"flex",gap:6,alignItems:"center"
              }}>
                <span style={{fontSize:14}}>{t.icon}</span>
                {t.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      <div style={{maxWidth:"min(880px, 94vw)",margin:"0 auto",padding:"28px 24px 60px"}}>
        {tab === "register" && (
          <>
            <div style={{marginBottom:24}}>
              <div style={{fontSize:20,fontWeight:700,color:C.slate900,
                letterSpacing:"-0.02em",marginBottom:4}}>
                Register an image
              </div>
              <div style={{fontSize:13,color:C.slate500,lineHeight:1.6}}>
                Generates a 256-bit zero-watermark key via YOLO + DWT×3 + DCT, embeds a
                scattered LSB tamper seal, and stores everything in MongoDB Atlas with
                AES-256-GCM vault encryption.
              </div>
            </div>
            <RegisterPanel />
          </>
        )}
        {tab === "gateway" && (
          <>
            <div style={{marginBottom:24}}>
              <div style={{fontSize:20,fontWeight:700,color:C.slate900,
                letterSpacing:"-0.02em",marginBottom:4}}>
                Content authenticity gateway
              </div>
              <div style={{fontSize:13,color:C.slate500,lineHeight:1.6}}>
                Runs three-layer verification: dual-hash blacklist pre-check, scattered LSB
                tamper seal, 16×16 MAD localisation, and zero-watermark NC score against
                the selected platform threshold.
              </div>
            </div>
            <GatewayPanel />
          </>
        )}
        {tab === "results" && (
          <>
            <div style={{marginBottom:24}}>
              <div style={{fontSize:20,fontWeight:700,color:C.slate900,
                letterSpacing:"-0.02em",marginBottom:4}}>
                Detection results
              </div>
              <div style={{fontSize:13,color:C.slate500,lineHeight:1.6}}>
                All gateway runs synced from MongoDB Atlas.
                NC score ≥ platform threshold = ownership proven.
              </div>
            </div>
            <ResultsPanel />
          </>
        )}
      </div>
    </div>
  );
}
