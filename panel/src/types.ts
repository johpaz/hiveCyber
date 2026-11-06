export interface TargetRule {
  host: string;
  paths: string[];
  methods: string[];
  rate_limit_rps?: number | null;
  only_own_accounts: boolean;
}
export interface TimeWindow {
  allowed_days: string[];
  allowed_hours_utc?: [number, number] | null;
}
export interface Policy {
  program: string;
  targets: TargetRule[];
  excluded: string[];
  prohibited: string[];
  require_human_approval: string[];
  time_windows?: TimeWindow | null;
}
export interface PolicyVersion {
  version: number;
  status: 'draft' | 'active' | 'archived';
  policy: Policy;
  justification?: string | null;
  lifted_prohibitions?: string[];
  created_by: string;
  created_at: string;
  activated_at?: string;
}
export interface SecurityStatus {
  window?: { allowed_hours_utc: [number, number] | null; allowed_days: string[]; open_now: boolean } | null;
  required_headers?: string[] | null;
  unsafe_mode: boolean;
  allow_cli_exec: boolean;
  require_policy: boolean;
  operator_id: string;
  has_policy: boolean;
  active_policy_version: number | null;
  program: string | null;
  require_human_approval: string[] | null;
}
export interface Dashboard {
  agents: { total: number; enabled: number };
  runs: { total: number; running: number; interrupted: number; completed: number; failed: number };
  audit: { entries: number; verified: boolean; errors: number };
  scope: { has_policy: boolean; program: string | null; targets: number | null };
  unsafe_mode: boolean;
}
export interface Agent {
  id: string;
  name: string;
  role: string;
  description: string;
  enabled: boolean;
  status: string;
  provider_id?: string | null;
  model_id?: string | null;
  tool_allowlist_json?: string[] | null;
  skills_json?: string[] | null;
  workspace_scope_json?: unknown;
}
export interface AuditEntry {
  id: string;
  timestamp: string;
  tool: string;
  target: string;
  worker: string;
  run_id: string;
  operator_id: string;
  hash_chain_prev: string;
}
export const PROHIBITED = [
  'denial_of_service', 'credential_stuffing', 'social_engineering', 'automated_scanning',
  'data_access', 'destructive_test', 'social_media_contact', 'physical_testing',
] as const;
export const APPROVAL = ['exploit', 'data_access', 'destructive_test', 'credential_use'] as const;
export interface Run {
  id: string; kind: string; agent_id: string; thread_id: string; status: string;
  iterations_used: number; turns_used: number; created_at?: string; updated_at?: string;
}
export interface ProviderInfo { id: string; key_set: boolean; is_default: boolean; base_url?: string | null; model?: string | null }
export interface ProvidersResp { providers: ProviderInfo[]; default_provider: string; default_model: string }
export interface ModelInfo { provider_id: string; model_id: string; context_window: number; input_per_1m: number; output_per_1m: number }
export interface DoctorResp { platform: string; sandbox_available: boolean; allow_unsandboxed: boolean; obscura_mcp: boolean; obscura_path?: string | null; tools: { name: string; binary: string; ok: boolean }[] }
export interface ActivityAgent { id: string; name?: string; role?: string; enabled?: boolean; working: boolean }
export interface ActivityTask { id: string; worker_id: string; status: string; description?: string | null; progress?: number | null; updated_at?: string }
export interface ActivityTrace { id: string; agent_id: string; tool_name: string; success?: boolean | null; duration_ms?: number; created_at: string }
export interface Activity { now: string; agents: ActivityAgent[]; tasks: ActivityTask[]; traces: ActivityTrace[]; running_jobs: number }
