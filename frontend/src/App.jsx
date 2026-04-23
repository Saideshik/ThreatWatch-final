import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Shield, AlertTriangle, Activity, Server, Search,
  RefreshCw, Zap, Radio, X, Filter, Target, Clock,
  CheckCircle, AlertOctagon, Eye,
  BarChart2, Cpu, Wifi, WifiOff
} from 'lucide-react'

// ════════════════════════════════════════════════════════════════════════════
// CHANGE THIS to your Railway URL after deploying backend
// ════════════════════════════════════════════════════════════════════════════
const API = 'https://threatwatch-production.up.railway.app'

// ─── Priority config ──────────────────────────────────────────────────────────
const P = {
  Critical: { color: 'var(--critical)', bg: 'var(--critical-bg)', border: 'var(--critical-border)' },
  High:     { color: 'var(--high)',     bg: 'var(--high-bg)',     border: 'var(--high-border)'     },
  Medium:   { color: 'var(--medium)',   bg: 'var(--medium-bg)',   border: 'var(--medium-border)'   },
  Low:      { color: 'var(--low)',      bg: 'var(--low-bg)',      border: 'var(--low-border)'      },
}
const pc = (p) => P[p] || P.Low

const STATUS = {
  Open:          { color: 'var(--text-secondary)', label: 'OPEN'          },
  Escalated:     { color: 'var(--critical)',        label: 'ESCALATED'     },
  Investigating: { color: 'var(--medium)',          label: 'INVESTIGATING' },
  Resolved:      { color: 'var(--green)',           label: 'RESOLVED'      },
}

function Badge({ text, color, bg, border }) {
  return (
    <span style={{
      color, background: bg, border: `1px solid ${border}`,
      padding: '1px 7px', borderRadius: 3,
      fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '.06em',
    }}>{text}</span>
  )
}

function PriorityBadge({ priority }) {
  const c = pc(priority)
  return <Badge text={priority.toUpperCase()} color={c.color} bg={c.bg} border={c.border} />
}

function StatusDot({ status }) {
  const s = STATUS[status] || STATUS.Open
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10,
      fontFamily: 'var(--font-mono)', color: s.color }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color,
        boxShadow: `0 0 4px ${s.color}` }} />
      {s.label}
    </span>
  )
}

function ScoreBar({ score }) {
  const pct = Math.min((score / 1000) * 100, 100)
  const color = score >= 400 ? 'var(--critical)' : score >= 250 ? 'var(--high)' : score >= 100 ? 'var(--medium)' : 'var(--low)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color,
          boxShadow: `0 0 6px ${color}`, transition: 'width .5s ease', borderRadius: 2 }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color, minWidth: 44, textAlign: 'right' }}>
        {score}
      </span>
    </div>
  )
}

function StatCard({ label, value, color, icon: Icon, pulse }) {
  return (
    <div style={{
      background: 'var(--bg-card)', border: `1px solid ${color}30`,
      borderRadius: 6, padding: '12px 16px',
      display: 'flex', alignItems: 'center', gap: 12,
      animation: pulse ? 'pulse-red 2s ease-in-out infinite' : 'none',
    }}>
      <div style={{ width: 34, height: 34, borderRadius: 6, background: `${color}18`,
        display: 'flex', alignItems: 'center', justifyContent: 'center', color, flexShrink: 0 }}>
        <Icon size={16} />
      </div>
      <div>
        <div style={{ fontSize: 20, fontFamily: 'var(--font-display)', fontWeight: 700, color, lineHeight: 1 }}>
          {value ?? '—'}
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-secondary)', letterSpacing: '.05em', marginTop: 2 }}>
          {label}
        </div>
      </div>
    </div>
  )
}

function AlertRow({ alert, isSelected, onClick }) {
  const c = pc(alert.priority)
  const isNew = alert._isNew
  return (
    <div
      onClick={() => onClick(alert)}
      className={isNew ? 'anim-fade-up' : ''}
      style={{
        padding: '11px 16px', borderBottom: '1px solid var(--border)',
        borderLeft: `3px solid ${isSelected ? c.color : 'transparent'}`,
        background: isSelected ? 'var(--bg-card-hover)' : 'transparent',
        cursor: 'pointer', transition: 'all .15s ease', position: 'relative',
      }}
      onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'var(--bg-card)' }}
      onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = 'transparent' }}
    >
      {isNew && (
        <span style={{ position: 'absolute', top: 8, right: 8, background: 'var(--critical)',
          color: '#fff', fontSize: 9, padding: '1px 5px', borderRadius: 3,
          fontFamily: 'var(--font-mono)' }}>NEW</span>
      )}
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'flex-start' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 3,
            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {alert.description}
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: 11, display: 'flex', alignItems: 'center', gap: 3 }}>
              <Server size={10} />{alert.agent_name}
            </span>
            <span style={{ color: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
              {alert.attack_type}
            </span>
            <StatusDot status={alert.status || 'Open'} />
            <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
              {new Date(alert.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
          <PriorityBadge priority={alert.priority} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: c.color }}>{alert.formula_score}</span>
        </div>
      </div>
    </div>
  )
}

function AIResponse({ text }) {
  if (!text) return null
  const sectionPatterns = [
    { label: 'IMMEDIATE ACTIONS', color: 'var(--critical)', icon: '🔴' },
    { label: 'INVESTIGATION STEPS', color: 'var(--medium)', icon: '🔍' },
    { label: 'PATCH / REMEDIATION', color: 'var(--green)', icon: '🔧' },
  ]
  let hasSections = sectionPatterns.some(sp => text.toUpperCase().includes(sp.label))
  if (!hasSections) {
    return <div style={{ fontSize: 12, lineHeight: 1.8, color: '#86efac', whiteSpace: 'pre-line' }}>{text}</div>
  }
  const sections = []
  for (let i = 0; i < sectionPatterns.length; i++) {
    const sp = sectionPatterns[i]
    const next = sectionPatterns[i + 1]
    const startIdx = text.toUpperCase().indexOf(sp.label)
    if (startIdx === -1) continue
    const endIdx = next ? text.toUpperCase().indexOf(next.label) : text.length
    const content = text.slice(startIdx + sp.label.length, endIdx !== -1 ? endIdx : undefined).replace(/^[\s:]+/, '')
    sections.push({ ...sp, content: content.trim() })
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {sections.map((s, i) => (
        <div key={i} style={{ borderRadius: 5, overflow: 'hidden', border: `1px solid ${s.color}22` }}>
          <div style={{ padding: '5px 10px', background: `${s.color}18`,
            fontSize: 10, fontFamily: 'var(--font-mono)', color: s.color,
            letterSpacing: '.06em', display: 'flex', alignItems: 'center', gap: 6 }}>
            {s.icon} {s.label}
          </div>
          <div style={{ padding: '8px 10px', background: `${s.color}06`,
            fontSize: 12, lineHeight: 1.8, color: 'var(--text-primary)', whiteSpace: 'pre-line' }}>
            {s.content}
          </div>
        </div>
      ))}
    </div>
  )
}

function DetailPanel({ alert, onClose, onAction }) {
  const c = pc(alert.priority)
  const [actionLoading, setActionLoading] = useState(null)
  const [currentStatus, setCurrentStatus] = useState(alert.status || 'Open')

  useEffect(() => { setCurrentStatus(alert.status || 'Open') }, [alert.id, alert.status])

  const handleAction = async (action) => {
    setActionLoading(action)
    try {
      const res = await fetch(`${API}/alerts/${alert.id}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      })
      if (res.ok) { setCurrentStatus(action); onAction(alert.id, action) }
    } catch (e) { console.error(e) }
    finally { setActionLoading(null) }
  }

  const actions = [
    { label: 'Escalate',    value: 'Escalated',     color: 'var(--critical)', icon: AlertOctagon },
    { label: 'Investigate', value: 'Investigating',  color: 'var(--medium)',   icon: Eye          },
    { label: 'Resolve',     value: 'Resolved',       color: 'var(--green)',    icon: CheckCircle  },
  ]

  return (
    <div className="anim-slide-in" style={{
      width: 400, background: 'var(--bg-panel)', borderLeft: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column', overflowY: 'auto', flexShrink: 0,
    }}>
      <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)',
        background: c.bg, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <PriorityBadge priority={alert.priority} />
          <StatusDot status={currentStatus} />
          <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>#{alert.id}</span>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none',
          color: 'var(--text-secondary)', cursor: 'pointer', padding: 4, display: 'flex' }}>
          <X size={15} />
        </button>
      </div>
      <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 14, flex: 1 }}>
        <div>
          <Label>Alert Description</Label>
          <p style={{ marginTop: 5, fontSize: 13, lineHeight: 1.55, fontWeight: 500 }}>{alert.description}</p>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px 14px' }}>
          <Field label="Agent / Host"   value={alert.agent_name}          icon={<Server size={10}/>}    mono />
          <Field label="Wazuh Severity" value={`Level ${alert.severity}`} icon={<Activity size={10}/>}  />
          <Field label="Formula Score"  value={alert.formula_score}       icon={<Zap size={10}/>}       mono color={c.color} />
          <Field label="Attack Type"    value={alert.attack_type}         icon={<Target size={10}/>}    />
          <Field label="MITRE Tactic"   value={alert.mitre_tactic}        icon={<BarChart2 size={10}/>} />
          <Field label="Timestamp"      value={new Date(alert.timestamp).toLocaleString()} icon={<Clock size={10}/>} />
        </div>
        <ScoreBar score={alert.formula_score} />
        <hr style={{ border: 'none', borderTop: '1px solid var(--border)' }} />
        <div>
          <Label icon={<Cpu size={11}/>}>AI Classification</Label>
          <div style={{ marginTop: 7, padding: '10px 12px', background: 'var(--accent-dim)',
            border: '1px solid rgba(56,189,248,0.2)', borderRadius: 5,
            color: '#93c5fd', fontSize: 12, lineHeight: 1.65 }}>
            {alert.ai_classification}
          </div>
        </div>
        <div>
          <Label icon={<Shield size={11}/>}>Response Recommendation</Label>
          <div style={{ marginTop: 7 }}><AIResponse text={alert.ai_response} /></div>
        </div>
        <div style={{ marginTop: 'auto', paddingTop: 8 }}>
          <Label>Take Action</Label>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            {actions.map(({ label, value, color, icon: Icon }) => {
              const isActive = currentStatus === value
              const isLoading = actionLoading === value
              return (
                <button key={value} onClick={() => handleAction(value)} disabled={!!actionLoading}
                  style={{
                    flex: 1, padding: '8px 4px',
                    background: isActive ? `${color}20` : 'none',
                    border: `1px solid ${isActive ? color : `${color}44`}`,
                    borderRadius: 5, color: isActive ? color : `${color}aa`,
                    fontSize: 11, fontFamily: 'var(--font-mono)', cursor: 'pointer',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5,
                    transition: 'all .15s ease',
                    opacity: actionLoading && !isLoading ? 0.5 : 1,
                  }}
                  onMouseEnter={e => { if (!isActive && !actionLoading) e.currentTarget.style.background = `${color}15` }}
                  onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'none' }}
                >
                  {isLoading ? <span className="spin">↻</span> : <Icon size={12} />}
                  {label}
                </button>
              )
            })}
          </div>
          {currentStatus !== 'Open' && (
            <div style={{ marginTop: 8, textAlign: 'center' }}>
              <button onClick={() => handleAction('Open')} style={{
                background: 'none', border: 'none', color: 'var(--text-muted)',
                fontSize: 11, cursor: 'pointer', textDecoration: 'underline', fontFamily: 'var(--font-mono)',
              }}>Reset to Open</button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Label({ children, icon }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5,
      color: 'var(--text-secondary)', fontSize: 10,
      letterSpacing: '.08em', textTransform: 'uppercase', fontWeight: 600 }}>
      {icon}{children}
    </div>
  )
}

function Field({ label, value, icon, mono, color }) {
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 3,
        color: 'var(--text-muted)', fontSize: 10, marginBottom: 2 }}>{icon}{label}</div>
      <div style={{ color: color || 'var(--text-primary)', fontSize: 12,
        fontFamily: mono ? 'var(--font-mono)' : 'var(--font-body)' }}>{value}</div>
    </div>
  )
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [alerts,        setAlerts]        = useState([])
  const [summary,       setSummary]       = useState(null)
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState(null)
  const [selected,      setSelected]      = useState(null)
  const [search,        setSearch]        = useState('')
  const [filterPri,     setFilterPri]     = useState('All')
  const [filterAtk,     setFilterAtk]     = useState('All')
  const [isLive,        setIsLive]        = useState(true)
  const [lastUpdate,    setLastUpdate]    = useState(null)
  const [newCount,      setNewCount]      = useState(0)
  const sseRef = useRef(null)

  const fetchAll = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    setError(null)
    try {
      const [ar, sr] = await Promise.all([
        fetch(`${API}/alerts`),
        fetch(`${API}/alerts/summary`),
      ])
      if (!ar.ok || !sr.ok) throw new Error(`HTTP ${ar.status}`)
      const ad = await ar.json()
      const sd = await sr.json()
      setAlerts(ad.alerts || [])
      setSummary(sd)
      setLastUpdate(new Date())
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])

  useEffect(() => {
    sseRef.current?.close()
    if (!isLive) return
    const es = new EventSource(`${API}/alerts/stream/live`)
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data)
        if (data.type === 'status_update') {
          setAlerts(prev => prev.map(a => a.id === data.id ? { ...a, status: data.status } : a))
          setSelected(prev => prev?.id === data.id ? { ...prev, status: data.status } : prev)
          return
        }
        setAlerts(prev => {
          if (prev.find(a => a.id === data.id)) return prev
          setNewCount(c => c + 1)
          setLastUpdate(new Date())
          return [{ ...data, _isNew: true }, ...prev].sort((a, b) => b.formula_score - a.formula_score)
        })
        setSummary(prev => prev ? { ...prev, total: (prev.total || 0) + 1 } : prev)
      } catch {}
    }
    es.onerror = () => {}
    sseRef.current = es
    return () => es.close()
  }, [isLive])

  const handleAction = (alertId, action) => {
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: action } : a))
    setSelected(prev => prev?.id === alertId ? { ...prev, status: action } : prev)
  }

  const filtered = alerts.filter(a => {
    if (filterPri !== 'All' && a.priority !== filterPri) return false
    if (filterAtk !== 'All' && a.attack_type !== filterAtk) return false
    if (search) {
      const q = search.toLowerCase()
      return a.description.toLowerCase().includes(q) || a.agent_name.toLowerCase().includes(q) || a.attack_type.toLowerCase().includes(q)
    }
    return true
  })

  const attackTypes = ['All', ...new Set(alerts.map(a => a.attack_type))]

  const handleRefresh = async () => {
    await fetch(`${API}/refresh`, { method: 'POST' }).catch(() => {})
    setNewCount(0)
    fetchAll(true)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <header style={{
        background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)',
        padding: '0 18px', height: 50, display: 'flex', alignItems: 'center',
        justifyContent: 'space-between', flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Shield size={19} style={{ color: 'var(--accent)' }} />
          <span style={{ fontFamily: 'var(--font-display)', fontSize: 17, fontWeight: 700, letterSpacing: '.06em' }}>
            THREAT<span style={{ color: 'var(--accent)' }}>WATCH</span>
          </span>
          <span style={{ width: 1, height: 18, background: 'var(--border)' }} />
          <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '.05em' }}>
            AI-DRIVEN ATTACK SIMULATION & DEFENSE EVALUATION
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {newCount > 0 && (
            <span style={{ background: 'var(--critical-bg)', border: '1px solid var(--critical-border)',
              color: 'var(--critical)', fontSize: 10, padding: '2px 8px', borderRadius: 10,
              fontFamily: 'var(--font-mono)' }}>+{newCount} NEW</span>
          )}
          {lastUpdate && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {lastUpdate.toLocaleTimeString()}
            </span>
          )}
          <button onClick={() => { setIsLive(v => !v); setNewCount(0) }} style={{
            display: 'flex', alignItems: 'center', gap: 5,
            background: isLive ? 'var(--green-dim)' : 'var(--bg-card)',
            border: `1px solid ${isLive ? 'rgba(61,220,132,.4)' : 'var(--border)'}`,
            borderRadius: 4, padding: '5px 10px', cursor: 'pointer',
            color: isLive ? 'var(--green)' : 'var(--text-secondary)',
            fontSize: 10, fontFamily: 'var(--font-mono)',
          }}>
            {isLive ? <><span className="blink"><Wifi size={11}/></span> LIVE</> : <><WifiOff size={11}/> PAUSED</>}
          </button>
          <button onClick={handleRefresh} style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4,
            padding: '5px 8px', color: 'var(--text-secondary)', cursor: 'pointer', display: 'flex',
          }}>
            <span className={loading ? 'spin' : ''}><RefreshCw size={13}/></span>
          </button>
        </div>
      </header>

      {error && (
        <div style={{ background: 'rgba(255,58,58,.08)', borderBottom: '1px solid rgba(255,58,58,.2)',
          padding: '6px 18px', color: '#ff8888', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
          ⚠ {error} — Showing mock data for demo
        </div>
      )}

      {summary && (
        <div style={{ padding: '10px 18px', borderBottom: '1px solid var(--border)',
          background: 'var(--bg-panel)', flexShrink: 0,
          display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(140px,1fr))', gap: 8 }}>
          <StatCard label="TOTAL ALERTS"  value={summary.total}    color="var(--accent)"   icon={Activity} />
          <StatCard label="CRITICAL"      value={summary.critical} color="var(--critical)"  icon={AlertTriangle} pulse={summary.critical > 0} />
          <StatCard label="HIGH"          value={summary.high}     color="var(--high)"      icon={Zap} />
          <StatCard label="MEDIUM"        value={summary.medium}   color="var(--medium)"    icon={Filter} />
          <StatCard label="MOST AFFECTED" value={summary.most_affected_agent} color="var(--purple)" icon={Server} />
          <StatCard label="TOP ATTACK"    value={summary.top_attack_categories?.[0]?.name || '—'} color="var(--green)" icon={Target} />
        </div>
      )}

      <div style={{ padding: '8px 18px', borderBottom: '1px solid var(--border)',
        background: 'var(--bg-panel)', flexShrink: 0,
        display: 'flex', gap: 8, alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1, maxWidth: 280 }}>
          <Search size={12} style={{ position: 'absolute', left: 9, top: '50%',
            transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search alerts, agents, attack types..."
            style={{ width: '100%', background: 'var(--bg-card)', border: '1px solid var(--border)',
              borderRadius: 4, padding: '5px 9px 5px 28px', color: 'var(--text-primary)',
              fontSize: 12, outline: 'none', fontFamily: 'var(--font-body)' }} />
        </div>
        <Sel value={filterPri} onChange={e => setFilterPri(e.target.value)}>
          {['All','Critical','High','Medium','Low'].map(v => <option key={v} value={v}>{v}</option>)}
        </Sel>
        <Sel value={filterAtk} onChange={e => setFilterAtk(e.target.value)}>
          {attackTypes.map(v => <option key={v} value={v}>{v}</option>)}
        </Sel>
        <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          {filtered.length} / {alerts.length}
        </span>
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto', borderRight: selected ? '1px solid var(--border)' : 'none' }}>
          {loading && alerts.length === 0
            ? <Loader />
            : filtered.length === 0
              ? <Empty />
              : filtered.map(a => (
                  <AlertRow key={a.id} alert={a} isSelected={selected?.id === a.id} onClick={setSelected} />
                ))
          }
        </div>
        {selected && <DetailPanel alert={selected} onClose={() => setSelected(null)} onAction={handleAction} />}
      </div>
    </div>
  )
}

function Sel({ children, value, onChange }) {
  return (
    <select value={value} onChange={onChange} style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4,
      padding: '5px 9px', color: 'var(--text-primary)', fontSize: 12,
      cursor: 'pointer', outline: 'none', fontFamily: 'var(--font-body)',
    }}>{children}</select>
  )
}

function Loader() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', height: '55%', gap: 10, color: 'var(--text-muted)' }}>
      <span className="spin" style={{ color: 'var(--accent)' }}><Activity size={26}/></span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>Loading threat data...</span>
    </div>
  )
}

function Empty() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', height: '55%', gap: 8, color: 'var(--text-muted)' }}>
      <Shield size={30} style={{ opacity: .3 }} />
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>No alerts match your filters</span>
    </div>
  )
}
