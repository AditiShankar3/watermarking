import { useState, useRef, useEffect } from "react";
import { registerImage, gatewayCheck, recoverCase, fetchResults, fetchPlatforms } from "./api";

// ── Design tokens ────────────────────────────────────────────────────────────
const C = {
  slate50:  "#f8fafc",
  slate100: "#f1f5f9",
  slate200: "#e2e8f0",
  slate300: "#cbd5e1",
  slate400: "#94a3b8",
  slate500: "#64748b",
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
  const [step, setStep] = useState("idle"); 
  const [result, setResult] = useState(null);
  const [errorLog, setErrorLog] = useState(null);

  const executeRegistration = async () => {
    if (!file) return;
    setStep("running");
    setErrorLog(null);
    setResult(null);

    try {
      const data = await registerImage(file.file);
      
      if (!data.ok) {
        setStep("idle");
        setErrorLog(data.detail || data.reason || "Registration failed");
        return;
      }

      setResult({
        filename: data.filename,
        signedName: data.signed_name,
        keyBalance: data.key_balance_pct,
        keyBits: data.key_len_bits,
        tamperHash: data.tamper_hash,
        vaultFile: data.vault_path,
        timestamp: data.timestamp,
      });
      setStep("done");
    } catch (err) {
      setStep("idle");
      setErrorLog(err.message);
    }
  };

  return (
    <div style={{display:"flex",flexDirection:"column",gap:20}}>
      <div>
        <div style={{fontSize:13,fontWeight:600,color:C.slate700,marginBottom:8}}>
          Original image
        </div>
        <DropZone label="Upload the original image to register" onFile={setFile} file={file} />
      </div>

      {errorLog && (
        <div style={{ background: C.red50, color: C.red500, padding: 12, borderRadius: 8, fontSize: 13, border: `1px solid ${C.red100}` }}>
          <strong>Error:</strong> {errorLog}
        </div>
      )}

      {file && step === "idle" && (
        <button
          onClick={executeRegistration}
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
          borderRadius:8,padding:14, display:"flex", justifyContent: "center", color: C.slate500
        }}>
           <span style={{animation:"spin 1s linear infinite", display:"inline-block", marginRight: 8}}>◐</span> Communicating with Backend Pipeline...
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
            <Stat label="Key length" value={`${result.keyBits} bits`} sub="5-replica majority vote" />
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
              ["Vault file", result.vaultFile],
              ["Ledger", "Local File System JSON"],
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

          <button onClick={()=>{setStep("idle");setFile(null);setResult(null);}}
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
  const [platforms, setPlatforms] = useState(null);
  const [platform, setPlatform] = useState("");
  const [step, setStep] = useState("idle");
  const [result, setResult] = useState(null);
  const [showRecover, setShowRecover] = useState(false);
  const [recovered, setRecovered] = useState(false);
  const [errorLog, setErrorLog] = useState(null);

  // Fetch real platforms from backend on mount
  useEffect(() => {
    fetchPlatforms()
      .then((data) => {
        setPlatforms(data);
        if (Object.keys(data).length > 0) {
          setPlatform(Object.keys(data)[0]);
        }
      })
      .catch((err) => console.error("Failed to load platforms:", err));
  }, []);

  const executeGatewayCheck = async () => {
    if (!file || !platform) return;
    setStep("running");
    setResult(null);
    setShowRecover(false);
    setRecovered(false);
    setErrorLog(null);

    try {
      const data = await gatewayCheck(file.file, platform);
      
      setResult({
        decision: data.decision,
        filename: data.filename,
        nc: data.nc_score,
        ncPass: data.nc_score >= platforms[platform].nc_threshold,
        bitAcc: data.bit_accuracy,
        matchedTo: data.matched_to || "N/A",
        registeredAt: data.matched_registered_at || "N/A",
        tamperCells: data.n_tampered_cells || 0,
        checkTime: data.check_time_s,
        caseId: data.case_id,
        tamperStatus: data.tamper_status,
        tamperDetail: data.tamper_detail
      });

      if (data.can_recover) setShowRecover(true);
      setStep("done");
    } catch (err) {
      setStep("idle");
      setErrorLog(err.message);
    }
  };

  const handleRecover = async () => {
    if (!result?.caseId) return;
    try {
      const rec = await recoverCase(result.caseId);
      if (rec.ok) {
        setRecovered(true);
      } else {
        alert("Recovery failed: " + rec.reason);
      }
    } catch (e) {
      alert("Error during recovery: " + e.message);
    }
  };

  if (!platforms) return <div style={{padding: 20}}>Loading platforms...</div>;

  return (
    <div style={{display:"flex",flexDirection:"column",gap:20}}>
      <div>
        <div style={{fontSize:13,fontWeight:600,color:C.slate700,marginBottom:8}}>
          Platform
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
          {Object.entries(platforms).map(([key,p])=>(
            <button key={key} onClick={()=>setPlatform(key)}
              style={{
                padding:"10px 8px",borderRadius:7,fontSize:11.5,fontWeight:600,
                border:`1.5px solid ${platform===key?C.teal500:C.slate200}`,
                background:platform===key?C.teal50:"white",
                color:platform===key?C.teal600:C.slate600,
                cursor:"pointer",lineHeight:1.4,textAlign:"center"
              }}>
              <div style={{fontSize: 20, marginBottom: 4}}>{p.icon}</div>
              <div style={{fontWeight:700}}>{p.name}</div>
              <div style={{fontSize:10,color:C.slate400,marginTop:4,fontWeight:400}}>
                NC ≥ {p.nc_threshold}
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

      {errorLog && (
        <div style={{ background: C.red50, color: C.red500, padding: 12, borderRadius: 8, fontSize: 13, border: `1px solid ${C.red100}` }}>
          <strong>Error:</strong> {errorLog}
        </div>
      )}

      {file && step === "idle" && (
        <button onClick={executeGatewayCheck} style={{
          background:C.slate800,color:"#fff",border:"none",borderRadius:8,
          padding:"11px 20px",fontWeight:600,fontSize:13,cursor:"pointer"
        }}>
          Run gateway check
        </button>
      )}

      {step === "running" && (
        <div style={{
          background:C.slate50,border:`1px solid ${C.slate200}`,
          borderRadius:8,padding:14, display:"flex", justifyContent: "center", color: C.slate500
        }}>
           <span style={{animation:"spin 1s linear infinite", display:"inline-block", marginRight: 8}}>◐</span> Analyzing image against backend registry...
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
            
            <div style={{fontSize: 13, color: C.slate700, marginBottom: 16, paddingBottom: 16, borderBottom: `1px solid ${result.decision==="ALLOW"?"#bbf7d0":"#fecaca"}`}}>
              <strong>Status:</strong> {result.tamperStatus} <br/>
              <span style={{color: C.slate500, fontSize: 12}}>{result.tamperDetail}</span>
            </div>

            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
            <Stat
                label="NC Score"
                value={
                  typeof result.nc === "number"
                    ? result.nc.toFixed(4)
                    : "—"
                }
                accent={
                  result.ncPass
                    ? C.teal600
                    : C.red500
                }
                sub={`threshold ${platforms[platform].nc_threshold}`}
              />

              <Stat
                label="Bit accuracy"
                value={
                  result.bitAcc != null
                    ? `${result.bitAcc}%`
                    : "—"
                }
                sub="≥87.5% expected"
              />
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
                <button onClick={handleRecover} style={{
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
              borderRadius:8,padding:"10px 20px",fontWeight:600,fontSize:13,cursor:"pointer", marginTop: 10
            }}>
            Check another image
          </button>
        </>
      )}
    </div>
  );
}

// ── Results panel ─────────────────────────────────────────────────────────────
function ResultsPanel() {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadResults = () => {
    setLoading(true);
    fetchResults()
      .then(setResults)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadResults();
  }, []);

  const blocked = results.filter(r=>r.decision==="BLOCK").length;
  const allowed = results.filter(r=>r.decision==="ALLOW").length;
  const validNcResults = results.filter(r=>r.nc_score > 0);
  const avgNc = validNcResults.length > 0 
    ? (validNcResults.reduce((a,r)=>a+r.nc_score,0) / validNcResults.length).toFixed(4)
    : "0.0000";

  if (loading) return <div style={{padding: 20}}>Loading results from backend...</div>;

  return (
    <div style={{display:"flex",flexDirection:"column",gap:20}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        <Stat label="Total runs"   value={results.length} />
        <Stat label="Blocked"      value={blocked}  accent={C.red500}  sub={results.length > 0 ? `${Math.round(blocked/results.length*100)}%` : "0%"} />
        <Stat label="Allowed"      value={allowed}  accent={C.teal600} sub={results.length > 0 ? `${Math.round(allowed/results.length*100)}%` : "0%"} />
        <Stat label="Avg NC score" value={avgNc} />
      </div>

      <div style={{
        background:C.slate50,border:`1px solid ${C.slate200}`,
        borderRadius:8,overflow:"hidden"
      }}>
        <div style={{
          display:"grid",
          gridTemplateColumns:"1fr 90px 80px 80px 120px 110px",
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
        {results.length === 0 ? (
           <div style={{padding: 20, textAlign: "center", fontSize: 13, color: C.slate500}}>No results logged yet.</div>
        ) : results.map((r,i)=>(
          <div key={i} style={{
            display:"grid",
            gridTemplateColumns:"1fr 90px 80px 80px 120px 110px",
            padding:"10px 14px",
            borderBottom: i<results.length-1?`1px solid ${C.slate100}`:"none",
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
              <Mono dim={r.nc_score===0}>{r.nc_score===0?"—":r.nc_score.toFixed(4)}</Mono>
            </div>
            <div>
              <Mono dim={r.bit_accuracy===0}>
                {r.bit_accuracy===0?"—":r.bit_accuracy.toFixed(1)+"%"}
              </Mono>
            </div>
            <div style={{fontSize:10,color:C.slate500}}>{r.tamper_status}</div>
            <div style={{fontSize:10,color:C.slate400}}>{r.check_time_s}s · <br/>{r.timestamp.split(' ')[1]}</div>
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
            Sync from Backend
          </div>
          <div style={{fontSize:11,color:C.slate400,marginTop:1}}>
            gateway_results ledger · {results.length} records loaded
          </div>
        </div>
        <button onClick={loadResults} style={{
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
          maxWidth:780,margin:"0 auto",
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
      <div style={{maxWidth:780,margin:"0 auto",padding:"28px 24px 60px"}}>
        {tab === "register" && (
          <>
            <div style={{marginBottom:24}}>
              <div style={{fontSize:20,fontWeight:700,color:C.slate900,
                letterSpacing:"-0.02em",marginBottom:4}}>
                Register an image
              </div>
              <div style={{fontSize:13,color:C.slate500,lineHeight:1.6}}>
                Generates a 256-bit zero-watermark key via YOLO + DWT×3 + DCT, embeds a
                scattered LSB tamper seal, and stores everything in the backend with
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
                All gateway runs synced directly from the backend system ledger.
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