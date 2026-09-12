// OnionSec API client conforming to docs/API.md

export interface EvidenceItem {
  type: string;
  description: string;
  source?: string;
  canonical_value?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence: number;
  target: string;
  analyzer: string;
  created_at: string;
  evidence?: EvidenceItem[];
  remediation?: string;
}

export interface ScanItem {
  id: string;
  target: string;
  started_at: string;
  ended_at: string;
  pages_seen: number;
  risk_score: number;
  findings_count: number;
  status: string;
}

export interface ScanDetail extends ScanItem {
  findings: Finding[];
}

export interface TargetItem {
  target: string;
  scan_count: number;
  latest_scan_at: string;
  latest_risk_score: number;
  latest_findings_count: number;
}

export interface AssetItem {
  type: string;
  canonical_value: string;
  first_seen: string;
  last_seen: string;
  co_occurring_targets: string[];
}

export interface DiffResult {
  target: string;
  old_scan: string;
  new_scan: string;
  risk_score_delta: number;
  new_findings: Finding[];
  resolved_findings: Finding[];
  persisting_findings: Finding[];
}

export interface GraphNodeData {
  id: string;
  label: string;
  type: string;
}

export interface GraphEdgeData {
  id?: string;
  source: string;
  target: string;
  label: string;
}

export interface GraphResponse {
  elements: {
    nodes: Array<{ data: GraphNodeData }>;
    edges: Array<{ data: GraphEdgeData }>;
  };
}

export interface StartScanRequest {
  target: string;
  async?: boolean;
  limits?: {
    max_pages?: number;
    max_body_byte?: number;
    page_timeout?: string;
    total_budget?: string;
  };
}

export class ApiClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl?: string, apiKey?: string) {
    if (typeof window !== "undefined") {
      this.baseUrl = baseUrl || localStorage.getItem("onionsec_api_url") || process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8080";
      this.apiKey = apiKey || localStorage.getItem("onionsec_api_key") || process.env.NEXT_PUBLIC_API_KEY || "";
    } else {
      this.baseUrl = baseUrl || process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8080";
      this.apiKey = apiKey || process.env.NEXT_PUBLIC_API_KEY || "";
    }
  }

  public setConfig(url: string, key: string) {
    this.baseUrl = url.replace(/\/+$/, "");
    this.apiKey = key;
    if (typeof window !== "undefined") {
      localStorage.setItem("onionsec_api_url", this.baseUrl);
      localStorage.setItem("onionsec_api_key", this.apiKey);
    }
  }

  public getConfig() {
    return {
      baseUrl: this.baseUrl,
      apiKey: this.apiKey,
    };
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      "Accept": "application/json",
      ...(options.headers as Record<string, string>),
    };

    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }

    if (options.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }

    const url = `${this.baseUrl}${path}`;
    const res = await fetch(url, { ...options, headers });

    if (!res.ok) {
      let errorMsg = `HTTP ${res.status}: ${res.statusText}`;
      try {
        const body = await res.json();
        if (body.message) {
          errorMsg = body.message;
        }
      } catch {
        // ignore json parse error
      }
      throw new Error(errorMsg);
    }

    return res.json() as Promise<T>;
  }

  async health(): Promise<{ status: string; version?: string }> {
    return this.request<{ status: string; version?: string }>("/healthz");
  }

  async listTargets(): Promise<{ targets: TargetItem[]; total: number }> {
    return this.request<{ targets: TargetItem[]; total: number }>("/v1/targets");
  }

  async listScans(target?: string): Promise<{ scans: ScanItem[]; total: number }> {
    const q = target ? `?target=${encodeURIComponent(target)}` : "";
    return this.request<{ scans: ScanItem[]; total: number }>(`/v1/scans${q}`);
  }

  async getScan(id: string): Promise<ScanDetail> {
    return this.request<ScanDetail>(`/v1/scans/${encodeURIComponent(id)}`);
  }

  async startScan(req: StartScanRequest): Promise<ScanDetail> {
    return this.request<ScanDetail>("/v1/scans", {
      method: "POST",
      body: JSON.stringify(req),
    });
  }

  async listFindings(params?: { target?: string; severity?: string; analyzer?: string }): Promise<{ findings: Finding[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.target) query.set("target", params.target);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.analyzer) query.set("analyzer", params.analyzer);
    const qs = query.toString() ? `?${query.toString()}` : "";
    return this.request<{ findings: Finding[]; total: number }>(`/v1/findings${qs}`);
  }

  async listAssets(params?: { target?: string; type?: string }): Promise<{ assets: AssetItem[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.target) query.set("target", params.target);
    if (params?.type) query.set("type", params.type);
    const qs = query.toString() ? `?${query.toString()}` : "";
    return this.request<{ assets: AssetItem[]; total: number }>(`/v1/assets${qs}`);
  }

  async getHistory(target: string): Promise<{ target: string; count: number; scans: ScanItem[] }> {
    return this.request<{ target: string; count: number; scans: ScanItem[] }>(`/v1/history?target=${encodeURIComponent(target)}`);
  }

  async getDiff(target: string, oldScan: string, newScan: string): Promise<DiffResult> {
    return this.request<DiffResult>(`/v1/diff?target=${encodeURIComponent(target)}&old_scan=${encodeURIComponent(oldScan)}&new_scan=${encodeURIComponent(newScan)}`);
  }

  async getGraph(target: string): Promise<GraphResponse> {
    return this.request<GraphResponse>(`/v1/graph?target=${encodeURIComponent(target)}`);
  }
}

export const api = new ApiClient();
