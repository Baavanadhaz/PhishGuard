export interface User {
  email: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
}

export interface ScanResult {
  id: number;
  url: string;
  result: 'safe' | 'phishing';
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
