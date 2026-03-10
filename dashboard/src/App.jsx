import React, { useState, useEffect } from 'react'
import './index.css'

function App() {
  const [score, setScore] = useState(100)
  const [events, setEvents] = useState([])
  const [actions, setActions] = useState([])
  const [status, setStatus] = useState('PROTECTED')
  const [wsStatus, setWsStatus] = useState('OFFLINE')

  useEffect(() => {
    // Determine the WS URL (works for both direct and proxied connections)
    const host = window.location.hostname || 'localhost'
    const wsUrl = `ws://${host}:8000/ws`
    
    console.log(`[Dashboard] Connecting to ${wsUrl}...`)
    const ws = new WebSocket(wsUrl)
    
    ws.onopen = () => {
      console.log('[Dashboard] Connected to Sentinel Brain')
      setWsStatus('ONLINE')
    }

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setScore(data.score)
        // Add unique IDs to events if they are missing
        const processedEvents = data.events.map((e, idx) => ({ ...e, id: e.id || `${e.time}-${idx}` }))
        setEvents(processedEvents)
        setActions(data.actions)
        
        if (data.score < 50) {
          setStatus('THREAT DETECTED')
        } else if (data.score < 90) {
          setStatus('CAUTION')
        } else {
          setStatus('PROTECTED')
        }
      } catch (err) {
        console.error('[Dashboard] Message Error:', err)
      }
    }

    ws.onerror = (error) => {
      console.error('[Dashboard] WebSocket Error:', error)
      setWsStatus('ERROR')
    }

    ws.onclose = () => {
      console.log('[Dashboard] Connection Closed')
      setWsStatus('OFFLINE')
    }

    return () => ws.close()
  }, [])

  return (
    <div className="dashboard-container">
      <header>
        <div className="logo">Sentinel // Autonomous</div>
        <div style={{ display: 'flex', gap: '20px' }}>
          <div className={`stat-pill ws-${wsStatus.toLowerCase()}`}>BRAIN: {wsStatus}</div>
          <div className="stat-pill">UPTIME: 04:32:11</div>
          <div className={`stat-pill ${score < 50 ? 'danger' : ''}`} style={{ borderColor: score < 50 ? '#ff2d55' : '#00f2ff' }}>
            STATUS: {status}
          </div>
        </div>
      </header>

      {/* Left Panel: Telemetry */}
      <aside className="panel">
        <div className="panel-header">System Telemetry</div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {events.map(e => (
            <div key={e.id} className={`event-item severity-${e.severity}`}>
              <div className="event-time">[{e.time}] {e.source}</div>
              <div>{e.msg}</div>
            </div>
          ))}
        </div>
      </aside>

      {/* Center Display: Trust Gauge */}
      <main className="center-display">
        <div className={`trust-gauge ${score < 50 ? 'danger' : ''}`}>
          <div className="score-value">{score}</div>
          <div className="score-label">Trust Score</div>
        </div>
        <div style={{ marginTop: '40px', textAlign: 'center' }}>
          <h3 style={{ color: 'var(--accent-cyan)', marginBottom: '10px' }}>ACTIVE DEFENSE ACTIVE</h3>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>Monitoring registry, network, and execution stacks.</p>
        </div>
      </main>

      {/* Right Panel: Countermeasures */}
      <aside className="panel">
        <div className="panel-header">Countermeasures</div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {actions.length === 0 ? (
            <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.8rem' }}>
              No active interventions.
            </div>
          ) : (
            actions.map((a, i) => (
              <div key={i} className="action-card">
                <div className="action-type">{a.type}</div>
                <div className="action-target">Target: {a.target}</div>
                <div className="event-time" style={{ marginTop: '5px' }}>Executed at {a.time}</div>
              </div>
            ))
          )}
        </div>
      </aside>

      {/* Bottom Panel: Analytics Bar */}
      <footer className="panel" style={{ gridColumn: '1 / -1', gridRow: '3', flexDirection: 'row', alignItems: 'center', padding: '0 20px' }}>
        <div style={{ flex: 1 }}>
          <div className="panel-header" style={{ border: 'none', padding: '0 0 10px 0' }}>Security Heuristics</div>
          <div style={{ display: 'flex', gap: '30px' }}>
            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>ANOMALY PROBABILITY</div>
              <div style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>1.22%</div>
            </div>
            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>YARA DEFINITIONS</div>
              <div style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>42,109</div>
            </div>
          </div>
        </div>
        <div style={{ width: '300px', height: '100px', background: 'rgba(0,242,255,0.05)', borderRadius: '8px', border: '1px solid var(--glass-border)' }}>
          {/* Chart Placeholder */}
          <div style={{ padding: '40px 10px', fontSize: '0.7rem', textAlign: 'center', color: 'var(--accent-cyan)' }}>
            [实时状态波形图] LIVE_TELEMETRY_STREAM...
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App
