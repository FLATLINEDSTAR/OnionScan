# OnionSec Security Dashboard

A modern React/Next.js dashboard for OnionSec, providing real-time visibility into Tor hidden service security scans, finding exploration, bipartite evidence correlation, and scan diffing.

## Prerequisites

- Node.js >= 18 (recommended: Node 20 or 22)
- Running OnionSec daemon (`cmd/onionsecd/`)

## Quick Start

1. Start the OnionSec API daemon:
   ```bash
   go run ./cmd/onionsecd -addr 127.0.0.1:8080 -db ~/.onionsec/onionsec.db
   ```

2. In this directory (`web/`), install dependencies and run the development server:
   ```bash
   npm install
   npm run dev
   ```

3. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Features

- **Fleet & Scan Overview**: Real-time fleet metrics (total targets, scans, risk scores) and detailed scan history table.
- **New Scan Modal**: Launch scans against target onion addresses directly from the web interface with configurable crawler limits (max pages, timeouts) and async background execution.
- **Finding Explorer**: Filter findings by severity (Critical, High, Medium, Low, Info), analyzer rule, target, or keyword search. Deep-dive inspection into finding confidence, source locations, and redacted corroborating evidence.
- **Evidence & Asset Matrix**: View bipartite asset store records (co-occurring IPs, TLS certs, emails, server signatures) highlighting cross-target deanonymization and infrastructure overlap.
- **Scan Diffing**: Directly compare scans for any target to isolate newly introduced, resolved, or persisting security issues and risk score deltas.
- **Interactive Evidence Graph (Cytoscape.js)**: Visualize bipartite correlation graphs showing audited targets, evidence nodes (IPs, TLS certs, fingerprints), and cross-target co-occurring peer links with force-directed, concentric, and ring layouts, zoom/pan controls, element inspectors, and PNG export.
- **API Configuration**: Easily change daemon endpoint URL and Bearer auth tokens in the dashboard UI.

## Build for Production

```bash
npm run build
npm run start
```
