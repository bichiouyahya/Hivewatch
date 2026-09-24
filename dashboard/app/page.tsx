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
import { SessionReplay } from './SessionReplay'

const WORLD_ATLAS_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'
// where the sensor is shown on the map, not tracked by the backend
const HONEYPOT_COORDS: [number, number] = [8.68, 50.11]

// rough country centroids, used to place origins when GeoIP is set up
const COUNTRY_COORDS: Record<string, [number, number]> = {
  'China': [104.2, 35.9], 'United States': [-98.5, 39.8], 'Russia': [60.0, 58.0],
  'Vietnam': [108.3, 14.1], 'Brazil': [-51.9, -14.2], 'India': [78.9, 20.6],
  'Germany': [10.4, 51.2], 'Netherlands': [5.3, 52.1], 'Indonesia': [113.9, -0.8],
  'South Korea': [127.8, 35.9], 'Ukraine': [31.2, 48.4], 'France': [2.2, 46.2],
  'United Kingdom': [-3.4, 55.4], 'Iran': [53.7, 32.4], 'Turkey': [35.2, 39.0],
  'Japan': [138.3, 36.2], 'Canada': [-106.3, 56.1], 'Singapore': [103.8, 1.35],
  'Hong Kong': [114.1, 22.4], 'Taiwan': [121.0, 23.7], 'Poland': [19.1, 51.9],
  'Romania': [24.9, 45.9], 'Bulgaria': [25.5, 42.7], 'Spain': [-3.7, 40.5],
  'Italy': [12.6, 41.9], 'Mexico': [-102.5, 23.6], 'Thailand': [100.9, 15.9],
  'Philippines': [121.8, 12.9], 'Malaysia': [101.98, 4.2], 'Australia': [133.8, -25.3],
  'Pakistan': [69.3, 30.4], 'Bangladesh': [90.4, 23.7], 'South Africa': [22.9, -30.6],
  'Egypt': [30.8, 26.8], 'Nigeria': [8.7, 9.1], 'Argentina': [-63.6, -38.4],
}

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'
// only needed when the API is exposed directly
const API_TOKEN = process.env.NEXT_PUBLIC_API_TOKEN ?? ''
const WS_URL =
  API_URL.replace(/^http/, 'ws') +
  '/ws/events' +
  (API_TOKEN ? `?token=${encodeURIComponent(API_TOKEN)}` : '')

const authHeaders: HeadersInit = API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {}

function apiFetch(path: string) {
  return fetch(`${API_URL}${path}`, { headers: authHeaders })
}

// links opened in a new tab can't send headers, so pass the token in the URL
function apiLink(path: string) {
  if (!API_TOKEN) return `${API_URL}${path}`
  return `${API_URL}${path}${path.includes('?') ? '&' : '?'}token=${encodeURIComponent(API_TOKEN)}`
}
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
  events_last_minute: number
  events_by_service: Record<string, number>
}

type CountryCount = { country: string; count: number }

type SessionItem = {
  id: string
  service: string
  source_ip: string
  country: string | null
  started_at: string
  ended_at: string | null
  command_count: number
  has_recording: boolean
}

type CommandStat = {
  command: string
  executions: number
  unique_attackers: number
  first_seen: string
  last_seen: string
  mitre_techniques: string[]
}

type AttackerStat = {
  source_ip: string
  country: string | null
  attacks: number
  services: string[]
  technique_count: number
  score: number
}

type TechniqueHeat = {
  technique: string
  name: string
  detections: number
  attackers: number
  last_seen: string | null
}

type TacticHeat = { tactic: string; techniques: TechniqueHeat[] }

type AttackOrigin = {
  source_ip: string
  country: string | null
  city: string | null
  latitude: number
  longitude: number
  events: number
}

type AlertItem = {
  severity: string
  technique: string
  title: string
  service: string
  source_ip: string
  created_at: string
}

type IocItem = {
  ioc_type: string
  value: string
  source_service: string
  hit_count: number
  confidence: number
}

type FeedItem = {
  time: string
  protocol: string
  ip: string
  title: string
  detail: string
  severity: string
}

type ActivityBucket = { time: string; ssh: number; http: number }


// scaled against the busiest cell and log-shaped, otherwise one noisy
// technique makes everything else look empty
function heatStyle(detections: number, max: number): React.CSSProperties {
  if (detections === 0) return { background: '#1b1b1b', borderColor: '#262626' }
  const ratio = Math.log(detections + 1) / Math.log(Math.max(max, 2) + 1)
  return {
    background: `rgba(245, 197, 24, ${(0.12 + ratio * 0.5).toFixed(3)})`,
    borderColor: `rgba(245, 197, 24, ${(0.3 + ratio * 0.5).toFixed(3)})`,
  }
}

function severityForTechniques(t: string[]): string {
  if (t.includes('T1110') || t.includes('T1552.001')) return 'CRITICAL'
  if (t.length > 0) return 'HIGH'
  return 'LOW'
}

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

type PlottedOrigin = { key: string; label: string; coords: [number, number]; events: number }

function AttackMap({
  origins,
  countries,
}: {
  origins: AttackOrigin[]
  countries: CountryCount[]
}) {
  // use real coordinates when GeoIP resolved them, else country centroids
  const plotted: PlottedOrigin[] =
    origins.length > 0
      ? origins.map(o => ({
          key: o.source_ip,
          label: [o.city, o.country].filter(Boolean).join(', ') || o.source_ip,
          coords: [o.longitude, o.latitude] as [number, number],
          events: o.events,
        }))
      : countries
          .filter(c => COUNTRY_COORDS[c.country])
          .map(c => ({
            key: c.country,
            label: c.country,
            coords: COUNTRY_COORDS[c.country],
            events: c.count,
          }))

  const busiest = Math.max(1, ...plotted.map(p => p.events))

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
          {plotted.slice(0, 40).map(o => (
            <Line key={`line-${o.key}`} from={o.coords} to={HONEYPOT_COORDS} className="route" />
          ))}
          {plotted.slice(0, 40).map((o, i) => (
            <Marker key={`dot-${o.key}`} coordinates={o.coords}>
              <circle
                r={3 + Math.round((o.events / busiest) * 4)}
                className="marker"
                style={{ fill: i === 0 ? MARKER_COLORS.http : MARKER_COLORS.ssh }}
              />
              <title>{`${o.label} — ${o.events} event${o.events === 1 ? '' : 's'}`}</title>
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
  const [sessions, setSessions] = useState<SessionItem[]>([])
  const [iocs, setIocs] = useState<IocItem[]>([])
  const [replaySession, setReplaySession] = useState<string | null>(null)
  const [commands, setCommands] = useState<CommandStat[]>([])
  const [attackers, setAttackers] = useState<AttackerStat[]>([])
  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [heatmap, setHeatmap] = useState<TacticHeat[]>([])
  const [origins, setOrigins] = useState<AttackOrigin[]>([])
  const pausedRef = useRef(paused)
  pausedRef.current = paused

  // render the map client-side only to avoid hydration mismatches
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])

  useEffect(() => {
    let cancelled = false
    const loadStats = () => {
      apiFetch(`/api/stats/overview`).then(res => res.json()).then(data => { if (!cancelled) setOverview(data) }).catch(() => {})
      apiFetch(`/api/stats/countries?limit=5`).then(res => res.json()).then(data => { if (!cancelled) setCountries(data) }).catch(() => {})
      apiFetch(`/api/sessions?limit=6`).then(res => res.json()).then(data => { if (!cancelled) setSessions(data.items ?? []) }).catch(() => {})
      apiFetch(`/api/iocs?limit=8`).then(res => res.json()).then(data => { if (!cancelled) setIocs(data.items ?? []) }).catch(() => {})
      apiFetch(`/api/stats/commands?limit=6`).then(res => res.json()).then(data => { if (!cancelled) setCommands(data) }).catch(() => {})
      apiFetch(`/api/stats/attackers?limit=5`).then(res => res.json()).then(data => { if (!cancelled) setAttackers(data) }).catch(() => {})
      apiFetch(`/api/alerts?limit=4`).then(res => res.json()).then(data => { if (!cancelled) setAlerts(data) }).catch(() => {})
      apiFetch(`/api/mitre/heatmap`).then(res => res.json()).then(data => { if (!cancelled) setHeatmap(data) }).catch(() => {})
      apiFetch(`/api/stats/origins?limit=200`).then(res => res.json()).then(data => { if (!cancelled) setOrigins(data) }).catch(() => {})
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

  return <div className="app-shell"><aside className="sidebar"><Logo /><nav><p>COMMAND CENTER</p>{[['Overview', LayoutDashboard], ['Live Activity', Activity], ['SSH Honeypot', Terminal], ['HTTP Honeypot', Globe2], ['Attackers', Users], ['Commands', Command], ['Requests', Zap]].map(([label, Icon], i) => <button className={i === 0 ? 'nav-item active' : 'nav-item'} key={label as string}><Icon size={16} />{label as string}{label === 'Live Activity' && <em>LIVE</em>}</button>)}<p>INTELLIGENCE</p>{[['Threat Intelligence', Shield], ['Geographic Activity', Globe2], ['Alerts', Bell], ['Logs', Database]].map(([label, Icon]) => <button className="nav-item" key={label as string}><Icon size={16} />{label as string}</button>)}</nav><div className="system"><p>SYSTEM STATUS</p><Status label="SSH Honeypot" /><Status label="HTTP Honeypot" /><Status label="Collector" /><Status label="Database" /></div><button className="settings"><Settings size={15} /> Settings</button></aside><main className="main"><header><div><div className="breadcrumb">HIVEWATCH <span>/</span> OVERVIEW</div><h1>Threat operations center</h1></div><div className="header-actions"><span className="live"><i className="dot online" />LIVE</span><span className="updated">Connected to {API_URL}</span><button className="icon-btn" aria-label="Search"><Search size={17} /></button><button className="icon-btn" aria-label="Notifications"><Bell size={17} /><b className="notification-dot" /></button><select value={range} onChange={e => setRange(e.target.value)} aria-label="Time range">{['LAST 15 MINUTES', 'LAST HOUR', 'LAST 24 HOURS', 'LAST 7 DAYS', 'LAST 30 DAYS'].map(x => <option key={x}>{x}</option>)}</select></div></header><div className="mobile-bar"><Logo /><Menu size={20} /></div><div className="metrics"><Metric icon={Activity} label="TOTAL ATTACKS" value={overview ? overview.total_events.toLocaleString() : '—'} spark={[]} /><Metric icon={Users} label="UNIQUE ATTACKERS" value={overview ? overview.unique_attackers.toLocaleString() : '—'} spark={[]} /><Metric icon={Terminal} label="SSH ATTEMPTS" value={sshCount.toLocaleString()} spark={[]} /><Metric icon={Globe2} label="HTTP REQUESTS" value={httpCount.toLocaleString()} spark={[]} /><Metric icon={Command} label="COMMANDS CAPTURED" value={overview ? overview.commands_captured.toLocaleString() : '—'} spark={[]} /><Metric icon={AlertTriangle} label="ACTIVE SESSIONS" value={overview ? overview.active_sessions.toLocaleString() : '—'} spark={[]} /></div><div className="dashboard-grid top-grid"><Card className="activity-card"><SectionTitle icon={Activity} action={<div className="tabs">{['ALL', 'SSH', 'HTTP'].map(x => <button className={protocol === x ? 'selected' : ''} onClick={() => setProtocol(x)} key={x}>{x}</button>)}</div>}>ATTACK ACTIVITY <span className="subtle">/since page opened</span></SectionTitle><div className="chart">{activityBuckets.length > 0 ? <ResponsiveContainer width="100%" height="100%"><AreaChart data={activityBuckets}><defs><linearGradient id="amberFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f5c518" stopOpacity={0.25} /><stop offset="100%" stopColor="#f5c518" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#2a2a2a" vertical={false} /><XAxis dataKey="time" tick={{ fill: '#777', fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: '#777', fontSize: 10 }} axisLine={false} tickLine={false} width={30} allowDecimals={false} /><Tooltip contentStyle={{ background: '#191919', border: '1px solid #3a3a3a', fontSize: 11 }} /><Area type="monotone" dataKey="ssh" name="SSH attacks" stroke="#f5c518" fill="url(#amberFill)" strokeWidth={2} /><Area type="monotone" dataKey="http" name="HTTP requests" stroke="#d99f00" fill="transparent" strokeWidth={1.5} /></AreaChart></ResponsiveContainer> : <div className="empty-hint">No activity yet this session — SSH into port 2222 or curl the honeypot to see it appear live.</div>}</div><div className="chart-foot"><span><i className="line-amber" />SSH attacks</span><span><i className="line-gold" />HTTP requests</span><b><CircleDot size={12} /> {overview?.active_sessions ?? 0} active sessions</b></div></Card><Card className="feed"><SectionTitle icon={Zap} action={<button className="pause" onClick={() => setPaused(!paused)}>{paused ? <Play size={13} /> : <Pause size={13} />}{paused ? 'RESUME' : 'PAUSE'}</button>}>LIVE ATTACK FEED</SectionTitle><div className="feed-status"><span className="dot online" />{paused ? 'Feed paused' : 'Streaming events'}<span>{liveEvents.length} events</span></div><div className="event-list">{filteredEvents.length === 0 && <div className="empty-hint">No events yet — SSH into port 2222 or curl a bait path to see live activity.</div>}{filteredEvents.map((e, i) => <div className={`event ${expanded === i ? 'expanded' : ''}`} key={`${e.time}-${i}`} onClick={() => setExpanded(expanded === i ? null : i)}><time>{e.time}</time><span className={`protocol ${e.protocol.toLowerCase()}`}>{e.protocol}</span><button className="ip" onClick={ev => { ev.stopPropagation(); setDrawer(e.ip) }}>{e.ip}</button><div className="event-copy"><strong>{e.title}</strong><small>{e.detail}</small>{expanded === i && <small className="event-extra">Sensor: {e.protocol === 'SSH' ? 'ssh-listener-01' : 'web-trap-02'} · session correlation enabled</small>}</div><Severity value={e.severity} /><ChevronRight size={14} className="chevron" /></div>)}</div></Card></div><div className="dashboard-grid map-grid"><Card><SectionTitle icon={Globe2} action={<span className="live-count"><i className="dot online" /> {origins.length > 0 ? origins.length : countries.length} sources active</span>}>GLOBAL ATTACK ORIGINS</SectionTitle>{mounted ? <AttackMap origins={origins} countries={countries} /> : <div className="map" />}</Card><Card className="sources"><SectionTitle icon={ArrowDownRight}>TOP ATTACK SOURCES</SectionTitle>{countries.length === 0 && <div className="empty-hint">No geo data yet — add a GeoLite2-City.mmdb to enable country lookups.</div>}{countries.map((c, i) => <div className="source" key={c.country}><span className="rank">0{i + 1}</span><div><div className="source-row"><b>{c.country}</b><span>{c.count.toLocaleString()}</span></div><div className="bar"><i style={{ width: `${(c.count / countries[0].count) * 100}%` }} /></div></div></div>)}</Card></div><div className="dashboard-grid analytics-grid"><Card><SectionTitle icon={Terminal}>SSH HONEYPOT <span className="status-chip">● LISTENER ONLINE</span></SectionTitle><div className="mini-stats"><div><b>{sshCount.toLocaleString()}</b><span>EVENTS</span></div><div><b>{overview?.unique_attackers ?? 0}</b><span>UNIQUE IPS</span></div><div><b>{overview?.active_sessions ?? 0}</b><span>ACTIVE</span></div></div></Card><Card><SectionTitle icon={Globe2}>HTTP HONEYPOT <span className="status-chip">● LISTENER ONLINE</span></SectionTitle><div className="mini-stats"><div><b>{httpCount.toLocaleString()}</b><span>REQUESTS</span></div><div><b>{overview?.unique_attackers ?? 0}</b><span>UNIQUE IPS</span></div></div></Card></div><div className="dashboard-grid bottom-grid" style={{ marginTop: 12 }}><Card><SectionTitle icon={Terminal} action={<span className="live-count">{sessions.filter(s => s.has_recording).length} recorded</span>}>SSH SESSION REPLAY</SectionTitle>{sessions.length === 0 && <div className="empty-hint">No sessions yet — SSH in with password <code>adminpass</code> to record one.</div>}{sessions.map(s => <div className="session-row" key={s.id}><time>{new Date(s.started_at).toLocaleTimeString('en-GB')}</time><button className="ip" onClick={() => setDrawer(s.source_ip)}>{s.source_ip}{s.country ? ` · ${s.country}` : ''}</button><span>{s.command_count} command{s.command_count === 1 ? '' : 's'}</span><span>{s.ended_at ? 'closed' : 'open'}</span><button className="replay-btn" disabled={!s.has_recording} onClick={() => setReplaySession(s.id)}>{s.has_recording ? 'REPLAY' : 'NO CAST'}</button></div>)}</Card><Card><SectionTitle icon={Shield} action={<span className="live-count">{iocs.length} shown</span>}>INDICATORS OF COMPROMISE</SectionTitle>{iocs.length === 0 && <div className="empty-hint">No indicators extracted yet.</div>}{iocs.map(i => <div className="ioc-row" key={`${i.ioc_type}-${i.value}`}><span className={`ioc-type ${i.ioc_type}`}>{i.ioc_type.replace('_', ' ')}</span><span className="ioc-value" title={i.value}>{i.value}</span><span className="ioc-hits">{i.hit_count}×</span><span className="ioc-conf">{i.confidence}</span></div>)}<div className="export-row"><button onClick={() => window.open(apiLink(`/api/iocs/export/stix`), '_blank')}>STIX 2.1</button><button onClick={() => window.open(apiLink(`/api/iocs/export/blocklist?format=iptables`), '_blank')}>IPTABLES</button><button onClick={() => window.open(apiLink(`/api/iocs/export/blocklist?format=nginx`), '_blank')}>NGINX</button><button onClick={() => window.open(apiLink(`/api/iocs/export/blocklist?format=plain`), '_blank')}>PLAIN</button><button onClick={() => window.open(apiLink(`/api/iocs/export/blocklist?format=csv`), '_blank')}>CSV</button></div></Card></div><Card className="commands"><SectionTitle icon={Shield} action={<span className="live-count">{heatmap.reduce((n, tac) => n + tac.techniques.filter(x => x.detections > 0).length, 0)} of {heatmap.reduce((n, tac) => n + tac.techniques.length, 0)} techniques seen</span>}>MITRE ATT&amp;CK COVERAGE</SectionTitle>{heatmap.length === 0 && <div className="empty-hint">Loading technique coverage…</div>}{heatmap.length > 0 && (() => { const max = Math.max(1, ...heatmap.flatMap(tac => tac.techniques.map(x => x.detections))); return <><div className="heatmap">{heatmap.map(tac => <div className="heat-col" key={tac.tactic}><div className="heat-tactic">{tac.tactic}</div>{tac.techniques.map(x => <div className={`heat-cell ${x.detections === 0 ? "cold" : ""}`} key={x.technique} style={heatStyle(x.detections, max)} title={`${x.technique} · ${x.name} · ${x.detections} detection(s) from ${x.attackers} attacker(s)`}><div className="heat-cell-top"><b>{x.technique}</b><em style={{color: x.detections ? "var(--primary)" : "#5f5f5c"}}>{x.detections}</em></div><span>{x.name}</span></div>)}</div>)}</div><div className="heat-legend"><i style={{background:"#1b1b1b",border:"1px solid #262626"}} />not seen<i style={{background:"rgba(245,197,24,0.22)"}} />low<i style={{background:"rgba(245,197,24,0.62)"}} />high<span style={{marginLeft:"auto"}}>columns follow ATT&amp;CK kill-chain order</span></div></>; })()}</Card><Card className="commands"><SectionTitle icon={Command} action={<span className="live-count">{commands.length} distinct</span>}>CAPTURED COMMANDS</SectionTitle>{commands.length === 0 && <div className="empty-hint">No commands captured yet — SSH in with password <code>adminpass</code> and run something.</div>}{commands.length > 0 && <div className="table-wrap"><table><thead><tr><th>COMMAND</th><th>RISK</th><th>TECHNIQUES</th><th>EXECUTIONS</th><th>UNIQUE ATTACKERS</th><th>FIRST SEEN</th><th>LAST SEEN</th></tr></thead><tbody>{commands.map(c=><tr key={c.command}><td><code>{c.command}</code></td><td><Severity value={severityForTechniques(c.mitre_techniques)} /></td><td>{c.mitre_techniques.join(", ") || "—"}</td><td>{c.executions}</td><td>{c.unique_attackers}</td><td>{new Date(c.first_seen).toLocaleTimeString("en-GB")}</td><td>{new Date(c.last_seen).toLocaleTimeString("en-GB")}</td></tr>)}</tbody></table></div>}</Card><div className="dashboard-grid bottom-grid"><Card><SectionTitle icon={Users} action={<span className="live-count">{attackers.length} seen</span>}>TOP ATTACKERS</SectionTitle>{attackers.length === 0 && <div className="empty-hint">No attackers recorded yet.</div>}{attackers.length > 0 && <div className="table-wrap"><table><thead><tr><th>IP ADDRESS</th><th>COUNTRY</th><th>EVENTS</th><th>SERVICES</th><th>TECHNIQUES</th><th>SCORE</th></tr></thead><tbody>{attackers.map(a=><tr key={a.source_ip}><td><button className="ip" onClick={() => setDrawer(a.source_ip)}>{a.source_ip}</button></td><td>{a.country ?? "—"}</td><td>{a.attacks.toLocaleString()}</td><td>{a.services.map(s=>s.toUpperCase()).join(" + ")}</td><td>{a.technique_count}</td><td><b className="score">{a.score}</b></td></tr>)}</tbody></table></div>}</Card><Card><SectionTitle icon={AlertTriangle} action={<span className="live-count">{alerts.length} recent</span>}>SECURITY ALERTS</SectionTitle>{alerts.length === 0 && <div className="empty-hint">Nothing has tripped a detection rule yet.</div>}{alerts.map(a=><div className="alert" key={`${a.technique}-${a.created_at}`}><Severity value={a.severity} /><div><b>{a.title}</b><small>{a.technique} · {a.service.toUpperCase()} / {a.source_ip} · {new Date(a.created_at).toLocaleTimeString("en-GB")}</small></div><button onClick={() => setDrawer(a.source_ip)}>VIEW</button></div>)}</Card></div><Card className="infra"><SectionTitle icon={Database}>HONEYPOT INFRASTRUCTURE</SectionTitle><div className="infra-grid">{["SSH Listener","HTTP Listener","Event Collector","Database"].map(x=><Status key={x} label={x} />)}<div className="infra-stat"><span>EVENTS (LAST MIN)</span><b>{overview?.events_last_minute ?? 0}</b></div><div className="infra-stat"><span>TOTAL STORED</span><b>{overview ? overview.total_events.toLocaleString() : "—"}</b></div><div className="infra-stat"><span>INDICATORS</span><b>{iocs.length > 0 ? iocs.length : "—"}</b></div></div></Card></main>{drawer && (() => { const a = attackers.find(x => x.source_ip === drawer); return <div className="drawer-backdrop" onClick={() => setDrawer(null)}><aside className="drawer" onClick={e => e.stopPropagation()}><button className="drawer-close" onClick={() => setDrawer(null)}><X size={18} /></button><div className="drawer-kicker"><Shield size={16} /> THREAT PROFILE</div><h2>{drawer}</h2><p className="country-line"><span className="dot critical" /> {a?.country ?? "no geo data"}</p><div className="threat-score"><span>THREAT SCORE</span><b>{a?.score ?? 0}</b><div><i style={{width:`${a?.score ?? 0}%`}} /></div></div><div className="drawer-stats"><div><b>{a ? a.attacks.toLocaleString() : 0}</b><span>TOTAL EVENTS</span></div><div><b>{a?.technique_count ?? 0}</b><span>TECHNIQUES</span></div><div><b>{a ? a.services.length : 0}</b><span>SERVICES</span></div><div><b>{sessions.filter(s => s.source_ip === drawer).length}</b><span>SESSIONS</span></div></div><h3>RECENT ACTIVITY</h3>{liveEvents.filter(e => e.ip === drawer).slice(0, 6).map((e, i) => <div className="timeline" key={i}><i /><span>{e.time} · {e.title}</span></div>)}{liveEvents.filter(e => e.ip === drawer).length === 0 && <div className="empty-hint">No activity since the dashboard was opened.</div>}<button className="primary-btn" onClick={() => window.open(apiLink(`/api/events?ip=${drawer}`), "_blank")}>VIEW RAW EVENTS FOR THIS IP</button></aside></div>; })()}{replaySession && <SessionReplay sessionId={replaySession} castUrl={apiLink(`/api/sessions/${replaySession}/replay`)} onClose={() => setReplaySession(null)} />}</div>
}
