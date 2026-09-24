'use client'

import { useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import '@xterm/xterm/css/xterm.css'

type Frame = [number, string, string]

// cap idle gaps so replays don't sit there doing nothing
const MAX_IDLE_GAP_SECONDS = 1.5

export function SessionReplay({
  sessionId,
  castUrl,
  onClose,
}: {
  sessionId: string
  /** recording URL, including the auth token if there is one */
  castUrl: string
  onClose: () => void
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState<'loading' | 'playing' | 'done' | 'error'>('loading')
  const [duration, setDuration] = useState(0)

  useEffect(() => {
    let cancelled = false
    const timers: ReturnType<typeof setTimeout>[] = []
    let term: { write: (s: string) => void; open: (el: HTMLElement) => void; dispose: () => void } | null = null

    const run = async () => {
      // imported here, not at module scope, since xterm needs the DOM
      const [{ Terminal }, { FitAddon }] = await Promise.all([
        import('@xterm/xterm'),
        import('@xterm/addon-fit'),
      ])

      let text: string
      try {
        const res = await fetch(castUrl)
        if (!res.ok) throw new Error(String(res.status))
        text = await res.text()
      } catch {
        if (!cancelled) setStatus('error')
        return
      }
      if (cancelled || !containerRef.current) return

      const lines = text.trim().split('\n')
      let header: { width?: number; height?: number }
      let frames: Frame[]
      try {
        header = JSON.parse(lines[0])
        frames = lines.slice(1).map(line => JSON.parse(line) as Frame)
      } catch {
        setStatus('error')
        return
      }

      const terminal = new Terminal({
        cols: header.width ?? 80,
        rows: header.height ?? 24,
        fontSize: 12,
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        convertEol: true, // recordings use \n, not \r\n
        cursorBlink: false,
        theme: { background: '#141414', foreground: '#d8d7d0', cursor: '#f5c518' },
      })
      const fit = new FitAddon()
      terminal.loadAddon(fit)
      terminal.open(containerRef.current)
      try {
        fit.fit()
      } catch {
        /* container not laid out yet; default size is fine */
      }
      term = terminal
      setStatus('playing')

      let playhead = 0
      let previous = 0
      for (const [offset, , data] of frames) {
        playhead += Math.min(Math.max(offset - previous, 0), MAX_IDLE_GAP_SECONDS)
        previous = offset
        timers.push(setTimeout(() => terminal.write(data), playhead * 1000))
      }
      setDuration(playhead)
      timers.push(setTimeout(() => !cancelled && setStatus('done'), playhead * 1000 + 150))
    }

    run()

    return () => {
      cancelled = true
      timers.forEach(clearTimeout)
      term?.dispose()
    }
  }, [sessionId, castUrl])

  return (
    <div className="replay-backdrop" onClick={onClose}>
      <aside className="replay-modal" onClick={e => e.stopPropagation()}>
        <button className="drawer-close" onClick={onClose} aria-label="Close replay">
          <X size={18} />
        </button>
        <div className="drawer-kicker">SESSION REPLAY</div>
        <h2>{sessionId}</h2>
        <div className="replay-meta">
          {status === 'loading' && 'Loading recording…'}
          {status === 'playing' && `Playing · ~${duration.toFixed(1)}s`}
          {status === 'done' && 'Playback finished'}
          {status === 'error' && 'No recording available for this session'}
        </div>
        <div className="replay-term" ref={containerRef} />
        <div className="replay-foot">
          asciicast v2 ·{' '}
          <a href={castUrl} target="_blank" rel="noreferrer">
            download raw cast
          </a>
        </div>
      </aside>
    </div>
  )
}
