export interface ScanResult {
  id: number;
  url: string;
  result: 'phishing' | 'safe';
  confidence: number;
  reason: string;
  created_at: string;
}

export interface DashboardStats {
  total_scans: number;
  phishing_count: number;
  safe_count: number;
  phishing_percentage: number;
}