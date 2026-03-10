# Sentinel: Autonomous Protection System

## Overview
Sentinel is an advanced, proactive security software that monitors system integrity and takes autonomous actions to neutralize threats based on a dynamic Trust Score.

## Components
- **Sentinel Agent (Watcher)**: Monitors system logs, registry, and network.
- **Sentinel Brain (Engine)**: ML-driven decision making and Trust Score management.
- **Sentinel Dashboard (UI)**: Visual representation of security status and active interventions.

## Technology Stack
- **Backend**: Python (System monitoring, ML logic)
- **Rules**: YARA (Signature-based detection)
- **Frontend**: Next.js, Vanilla CSS, Lucide Icons
- **Communication**: FastAPI / WebSockets for real-time score updates.
