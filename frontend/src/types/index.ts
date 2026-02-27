export interface Query {
  id: number;
  timestamp: string;
  domain: string;
  client_ip: string;
  client_hostname: string | null;
  query_type: string | null;
  status: string | null;
  server: string;
}

export interface AlertRule {
  id: number;
  name: string;
  description: string | null;
  domain_pattern: string | null;
  client_ip_pattern: string | null;
  client_hostname_pattern: string | null;
  exclude_domains: string | null;
  cooldown_minutes: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AlertRuleCreate {
  name: string;
  description?: string;
  domain_pattern?: string;
  client_ip_pattern?: string;
  client_hostname_pattern?: string;
  exclude_domains?: string;
  cooldown_minutes?: number;
  enabled?: boolean;
}

export interface Stats {
  queries_last_24h: number;
  blocks_last_24h: number;
}

export interface QuerySearchParams {
  search?: string;
  domain?: string;
  client_ip?: string;
  client_hostname?: string;
  server?: string;
  from_date?: string;
  to_date?: string;
  limit?: number;
  offset?: number;
}

export type ServerType = 'pihole' | 'adguard' | 'technitium';

export interface PiholeServer {
  id: number;
  name: string;
  url: string;
  password: string;
  username: string | null;
  server_type: ServerType;
  skip_ssl_verify: boolean;
  extra_config: Record<string, string> | null;
  enabled: boolean;
  display_order: number;
  is_source: boolean;
  sync_enabled: boolean;
  last_synced_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface PiholeServerCreate {
  name: string;
  url: string;
  password: string;
  username?: string;
  server_type?: ServerType;
  skip_ssl_verify?: boolean;
  extra_config?: Record<string, string>;
  enabled?: boolean;
  is_source?: boolean;
  sync_enabled?: boolean;
}

export interface AppSettingDetail {
  key: string;
  value: string | number | boolean | string[];
  value_type: string;
  description: string | null;
  requires_restart: boolean;
  updated_at: string | null;
}

export interface SettingsResponse {
  app_settings: Record<string, AppSettingDetail>;
  servers: PiholeServer[];
}

export interface DomainEntry {
  id?: number;
  domain: string;
  enabled: boolean;
  date_added?: string;
  date_modified?: string;
  comment?: string;
  groups?: number[];
}

export interface Statistics {
  queries_today: number;
  queries_week: number;
  queries_month: number;
  queries_total: number;
  queries_period: number;
  blocked_period: number;
  blocked_percentage: number;
  queries_hourly: Array<{ hour: string; queries: number; blocked: number }>;
  queries_daily: Array<{ date: string; queries: number; blocked: number }>;
  top_domains: Array<{ domain: string; count: number }>;
  top_blocked_domains: Array<{ domain: string; count: number }>;
  top_clients: Array<{ client_ip: string; client_hostname: string | null; count: number }>;
  queries_by_server: Array<{ server: string; queries: number; blocked: number; cached: number }>;
  unique_clients: number;
  most_active_client: { client_ip: string; client_hostname: string | null; count: number } | null;
  new_clients_24h: number;
}

export interface StatisticsParams {
  period?: string;
  servers?: string;
  clients?: string;
  from_date?: string;
  to_date?: string;
}

export interface StatisticsClientsParams {
  period?: string;
  servers?: string;
  from_date?: string;
  to_date?: string;
}

export interface ClientInfo {
  client_ip: string;
  client_hostname: string | null;
  count: number;
}

export interface BlockingStatus {
  id: number;
  name: string;
  blocking: boolean | null;
  auto_enable_at: string | null;
  error?: string;
}

export interface BlockingStatusResponse {
  servers: BlockingStatus[];
}

export interface BlockingSetRequest {
  enabled: boolean;
  duration_minutes?: number;
}

export interface BlockingSetResponse {
  success: boolean;
  server_id?: number;
  blocking?: boolean;
  auto_enable_at?: string | null;
  results?: Array<{
    server_id: number;
    name: string;
    success: boolean;
    blocking?: boolean | null;
    error?: string;
  }>;
}

// ============================================================================
// Authentication Types
// ============================================================================

export interface User {
  id: number;
  username: string;
  email: string | null;
  display_name: string | null;
  is_active: boolean;
  is_admin: boolean;
  oidc_provider: string | null;
  has_local_password: boolean;
  created_at: string | null;
  last_login_at: string | null;
}

export interface AuthCheckResponse {
  authenticated: boolean;
  user: User | null;
  setup_complete: boolean;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface SetupRequest {
  username: string;
  password: string;
  email?: string;
}

export interface UserCreate {
  username: string;
  password?: string;
  email?: string;
  display_name?: string;
  is_admin?: boolean;
}

export interface UserUpdate {
  email?: string;
  display_name?: string;
  password?: string;
  is_active?: boolean;
  is_admin?: boolean;
}

// ============================================================================
// OIDC Types
// ============================================================================

export interface OIDCProviderPublic {
  name: string;
  display_name: string;
}

export interface OIDCProvider {
  id: number;
  name: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  username_claim: string;
  email_claim: string;
  display_name_claim: string;
  groups_claim: string | null;
  admin_group: string | null;
  enabled: boolean;
  display_order: number;
  created_at: string;
  updated_at: string;
}

export interface OIDCProviderCreate {
  name: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes?: string;
  username_claim?: string;
  email_claim?: string;
  display_name_claim?: string;
  groups_claim?: string;
  admin_group?: string;
  enabled?: boolean;
}

export interface OIDCProviderUpdate {
  display_name?: string;
  issuer_url?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string;
  username_claim?: string;
  email_claim?: string;
  display_name_claim?: string;
  groups_claim?: string;
  admin_group?: string;
  enabled?: boolean;
}

// ============================================================================
// Notification Channel Types
// ============================================================================

export type NotificationChannelType = 'telegram' | 'pushover' | 'ntfy' | 'webhook' | 'discord';

export interface NotificationChannel {
  id: number;
  name: string;
  channel_type: NotificationChannelType;
  config: Record<string, unknown>;
  message_template: string | null;
  enabled: boolean;
  last_success_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  consecutive_failures: number;
  created_at: string;
  updated_at: string;
}

export interface NotificationChannelCreate {
  name: string;
  channel_type: NotificationChannelType;
  config: Record<string, unknown>;
  message_template?: string;
  enabled?: boolean;
}

export interface NotificationChannelUpdate {
  name?: string;
  config?: Record<string, unknown>;
  message_template?: string;
  enabled?: boolean;
}

export interface TemplateVariable {
  name: string;
  description: string;
  example: string;
}

export interface ChannelTypeConfigField {
  name: string;
  label: string;
  type: 'text' | 'password' | 'number' | 'select' | 'checkbox';
  required: boolean;
  placeholder?: string;
  options?: string[];
  description?: string;
}

export interface ChannelTypeInfo {
  type: NotificationChannelType;
  name: string;
  icon: string;
  config_fields: ChannelTypeConfigField[];
}

export interface TemplateVariablesResponse {
  variables: TemplateVariable[];
  default_template: string;
}

export interface ChannelTypesResponse {
  channel_types: ChannelTypeInfo[];
}

// ============================================================================
// API Key Types
// ============================================================================

export interface ApiKey {
  id: number;
  name: string;
  key_prefix: string;
  is_admin: boolean;
  expires_at: string | null;
  created_at: string | null;
  last_used_at: string | null;
}

export interface ApiKeyCreate {
  name: string;
  is_admin?: boolean;
  expires_at?: string;
}

export interface ApiKeyCreateResponse extends ApiKey {
  raw_key: string;
}

// ============================================================================
// Sync Types
// ============================================================================

export interface SyncPreviewSource {
  source: { name: string; server_type?: string };
  targets: { name: string }[];
  teleporter?: {
    backup_size_bytes: number;
    includes?: string[];
  };
  config?: {
    keys?: Record<string, string[]>;
    summary?: Record<string, number | boolean>;
  };
  error?: string;
}

export interface SyncPreview {
  sources?: SyncPreviewSource[];
  source?: SyncPreviewSource['source'];
  targets?: SyncPreviewSource['targets'];
  teleporter?: SyncPreviewSource['teleporter'];
  config?: SyncPreviewSource['config'];
  error?: string;
  message?: string;
}

export interface SyncItemsSynced {
  _teleporter_size_bytes?: number;
  _config_sections?: string[];
  _server_type?: string;
  [key: string]: unknown;
}

export interface SyncHistoryEntry {
  id: number;
  source_server_id: number;
  target_server_ids: number[];
  started_at: string;
  completed_at: string | null;
  sync_type: string;
  status: string;
  items_synced: SyncItemsSynced | null;
  errors: string[];
}
