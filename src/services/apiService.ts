/**
 * E-CYCLE Client API Service
 * Handles authenticated communication with the local backend.
 */

export interface UserSession {
  id: string;
  name: string;
  email: string;
  role: 'resident' | 'technician' | 'partner' | 'admin';
  partnerId?: string | null;
  token?: string;
}

export interface AdminStatsData {
  totalUsers: number;
  totalDevices: number;
  totalRequests: number;
  pendingRequests: number;
  assignedRequests: number;
  scheduledPickups: number;
  collectedDevices: number;
  completedRecycling: number;
  completedRepair: number;
  completedDonation: number;
  activeCollectors: number;
  activeRepairPartners: number;
  estimatedWeightKg: number;
  dailyTrends: { day: string; count: number }[];
  categoryData: { name: string; value: number }[];
  actionData: { name: string; value: number }[];
  partnerPerformance: { name: string; active: number; capacity: number; completed: number }[];
}

export interface RequestItem {
  id: string;
  owner: string;
  ownerEmail?: string;
  deviceId: string;
  deviceName: string;
  category: string;
  condition: string;
  action: 'repair' | 'donate' | 'recycle';
  recommendedAction: 'repair' | 'donate' | 'recycle';
  partnerId: string | null;
  partnerName: string | null;
  status: string;
  createdAt: number;
  pickupDate?: string | null;
  pickupSlot?: string | null;
  address?: string;
  locality?: string;
  pincode?: string;
  weight?: number;
  internalNotes?: string[];
  history: { status: string; at: number; user: string; note?: string }[];
}

export interface PartnerItem {
  id: string;
  name: string;
  type: 'repair' | 'donate' | 'recycle';
  categories: string[];
  locality: string;
  pincode: string;
  capacity: number;
  active: number;
  verified: boolean;
  specialization: string;
  available: boolean;
  isRealProvider?: boolean;
  needs?: string;
  contactPerson?: string;
  phone?: string;
}

const AUTH_KEY = 'ecycle_auth_user';
const TOKEN_KEY = 'ecycle_auth_token';

export function getSavedToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY);
}

/**
 * Safe fetch wrapper that handles network disconnects and connection errors.
 */
export async function safeFetch(url: string, options: RequestInit = {}): Promise<Response> {
  try {
    return await fetch(url, options);
  } catch {
    throw new Error('Unable to connect to server.');
  }
}

/**
 * Safely parses any Response as JSON.
 * If the response body is empty, HTML, or malformed, it handles it gracefully
 * without throwing "Unexpected end of JSON input".
 */
export async function safeParseJson<T = any>(
  res: Response,
  fallbackError = 'Request failed'
): Promise<T> {
  let text = '';
  try {
    text = await res.text();
  } catch {
    text = '';
  }

  let data: any = null;
  if (text && text.trim().length > 0) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    if (res.status === 401) {
      throw new Error(data?.error || 'Invalid email or password.');
    }
    if (res.status === 403) {
      throw new Error(data?.error || 'Access denied: You do not have permission.');
    }
    if (res.status === 404) {
      throw new Error(data?.error || 'Requested service or resource not found.');
    }
    if (res.status === 502 || res.status === 503 || res.status === 504 || res.status === 405) {
      throw new Error('Unable to connect to server.');
    }
    if (res.status >= 500) {
      throw new Error(data?.error || 'Login service temporarily unavailable.');
    }
    throw new Error(data?.error || fallbackError);
  }

  if (data === null) {
    return {} as T;
  }

  return data as T;
}

export async function authFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const token = getSavedToken();
  const headers = new Headers(options.headers || {});
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  return safeFetch(url, { ...options, headers });
}

// Session Helpers
export function getSavedSession(): UserSession | null {
  try {
    const raw = sessionStorage.getItem(AUTH_KEY) || localStorage.getItem(AUTH_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function saveSession(user: UserSession, token?: string) {
  sessionStorage.setItem(AUTH_KEY, JSON.stringify(user));
  if (token) {
    sessionStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(TOKEN_KEY, token);
  }
}

export function clearSession() {
  sessionStorage.removeItem(AUTH_KEY);
  sessionStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(AUTH_KEY);
  localStorage.removeItem(TOKEN_KEY);
}

// Auth API Calls
export async function loginUser(email: string, password: string): Promise<UserSession> {
  if (!email?.trim() || !password) {
    throw new Error('Email and password are required.');
  }

  const res = await safeFetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.trim(), password }),
  });

  const data = await safeParseJson<{ success: boolean; user: UserSession; token: string }>(
    res,
    'Invalid email or password.'
  );

  if (!data?.user) {
    throw new Error('Invalid email or password.');
  }

  saveSession(data.user, data.token);
  return data.user;
}

export async function registerCustomer(name: string, email: string, password: string): Promise<UserSession> {
  if (!name?.trim()) throw new Error('Please enter your full name');
  if (!email?.trim()) throw new Error('Please enter your email');
  if (!password || password.length < 6) throw new Error('Password must be at least 6 characters long.');

  const res = await safeFetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: name.trim(), email: email.trim(), password }),
  });

  const data = await safeParseJson<{ success: boolean; user: UserSession; token: string }>(
    res,
    'Failed to register account'
  );

  if (!data?.user) {
    throw new Error('Failed to register account');
  }

  saveSession(data.user, data.token);
  return data.user;
}

export async function resetPassword(email: string, newPassword?: string): Promise<string> {
  if (!email?.trim()) throw new Error('Email address is required.');

  const res = await authFetch('/api/auth/reset-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.trim(), newPassword: newPassword?.trim() }),
  });

  const data = await safeParseJson<{ success: boolean; message: string }>(
    res,
    'Password reset failed'
  );

  return data?.message || 'Password updated successfully.';
}

// Device API Calls
export interface DeviceItem {
  id: string;
  name: string;
  category: string;
  brand: string;
  model: string;
  age: number;
  condition: string;
  issue: string;
  pincode: string;
  locality: string;
  createdAt: number;
  working: boolean;
  powersOn: boolean;
  damage: boolean;
  battery: boolean;
  swollen: boolean;
  missing: boolean;
  usable: boolean;
  repairCost: number;
  replacementValue: number;
  photoId?: string;
  recommended?: 'repair' | 'donate' | 'recycle';
  reason?: string;
  owner?: string;
  ownerEmail?: string;
}

export async function fetchDevices(params: { ownerEmail?: string; role?: string } = {}): Promise<DeviceItem[]> {
  const query = new URLSearchParams();
  if (params.ownerEmail) query.set('ownerEmail', params.ownerEmail);
  if (params.role) query.set('role', params.role);

  const res = await authFetch(`/api/devices?${query.toString()}`);
  const data = await safeParseJson<{ devices: DeviceItem[] }>(res, 'Failed to load devices');
  return data.devices || [];
}

export async function saveDevice(device: Partial<DeviceItem>): Promise<DeviceItem> {
  const res = await authFetch('/api/devices', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(device),
  });
  const data = await safeParseJson<{ device: DeviceItem }>(res, 'Failed to save device');
  return data.device;
}

export async function removeDevice(id: string): Promise<boolean> {
  const res = await authFetch(`/api/devices/${id}`, { method: 'DELETE' });
  return res.ok;
}

// Admin Stats
export async function fetchAdminStats(): Promise<AdminStatsData> {
  const res = await authFetch('/api/admin/stats');
  const data = await safeParseJson<{ stats: AdminStatsData }>(res, 'Failed to load admin stats');
  return data.stats;
}

// Request API Calls
export async function createRequest(reqData: Partial<RequestItem>): Promise<RequestItem> {
  const res = await authFetch('/api/requests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(reqData),
  });
  const data = await safeParseJson<{ request: RequestItem }>(res, 'Failed to submit request');
  return data.request;
}

export async function fetchRequests(params: {
  status?: string;
  action?: string;
  search?: string;
  partnerId?: string;
  userEmail?: string;
  role?: string;
} = {}): Promise<RequestItem[]> {
  const query = new URLSearchParams();
  if (params.status) query.set('status', params.status);
  if (params.action) query.set('action', params.action);
  if (params.search) query.set('search', params.search);
  if (params.partnerId) query.set('partnerId', params.partnerId);
  if (params.userEmail) query.set('userEmail', params.userEmail);
  if (params.role) query.set('role', params.role);

  const res = await authFetch(`/api/requests?${query.toString()}`);
  const data = await safeParseJson<{ requests: RequestItem[] }>(res, 'Failed to fetch requests');
  return data.requests || [];
}

export async function assignRequestPartner(
  requestId: string,
  partnerId: string,
  adminUser: string,
  reason?: string
): Promise<RequestItem> {
  const res = await authFetch(`/api/requests/${requestId}/assign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ partnerId, adminUser, reason }),
  });

  const data = await safeParseJson<{ request: RequestItem }>(res, 'Failed to assign partner');
  return data.request;
}

export async function updateStatus(
  requestId: string,
  status: string,
  user: string,
  note?: string,
  optionalData?: {
    weight?: number;
    pickupDate?: string;
    pickupSlot?: string;
    internalNote?: string;
    diagnosis?: string;
    repairCost?: number;
    partsRequired?: string;
    isUnrepairable?: boolean;
    collectionNotes?: string;
    address?: string;
    handoverCode?: string;
    codeUsed?: boolean;
  }
): Promise<RequestItem> {
  const res = await authFetch(`/api/requests/${requestId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, user, note, ...optionalData }),
  });

  const data = await safeParseJson<{ request: RequestItem }>(res, 'Failed to update request status');
  return data.request;
}

export async function addInternalNote(requestId: string, note: string, user: string): Promise<string[]> {
  const res = await authFetch(`/api/requests/${requestId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note, user }),
  });

  const data = await safeParseJson<{ internalNotes: string[] }>(res, 'Failed to add note');
  return data.internalNotes || [];
}

// Partner API Calls
export async function fetchPartners(): Promise<PartnerItem[]> {
  const res = await authFetch('/api/partners');
  const data = await safeParseJson<{ partners: PartnerItem[] }>(res, 'Failed to load partners');
  return data.partners || [];
}

export async function savePartner(partner: Partial<PartnerItem>): Promise<PartnerItem> {
  const res = await authFetch('/api/partners', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(partner),
  });

  const data = await safeParseJson<{ partner: PartnerItem }>(res, 'Failed to save partner');
  return data.partner;
}

export async function togglePartnerAvailability(id: string): Promise<PartnerItem> {
  const res = await authFetch(`/api/partners/${id}/toggle`, {
    method: 'POST',
  });

  const data = await safeParseJson<{ partner: PartnerItem }>(res, 'Failed to toggle availability');
  return data.partner;
}

// ==========================================
// Module 3: AI Recommendation
// ==========================================
export interface RecommendationData {
  recommendedAction: 'repair' | 'donate' | 'recycle' | 'refurbish' | 'specialist_assessment';
  actionTitle?: string;
  isSafe: boolean;
  safetyConsiderations: string;
  explanation: string;
  alternativeAction: string;
  missingInformation: string;
  uncertainty: string;
  source: string;
}

export async function fetchRecommendation(deviceData: {
  category: string;
  age?: number;
  condition?: string;
  damage?: string;
  repairCost?: number;
  replacementValue?: number;
  swollen?: boolean;
  batteryIssues?: boolean;
  powersOn?: boolean;
  missingParts?: boolean;
  working?: boolean;
}): Promise<RecommendationData> {
  const res = await safeFetch('/api/recommend', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(deviceData),
  });

  const data = await safeParseJson<RecommendationData & { success?: boolean; error?: string }>(
    res,
    'Failed to obtain recommendation'
  );
  if (data.success === false) throw new Error(data.error || 'Failed to obtain recommendation');
  return data;
}

// ==========================================
// Module 4: AI Chatbot
// ==========================================
export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  source?: string;
}

export async function sendChatMessage(
  message: string,
  history: ChatMessage[] = [],
  userEmail?: string | null,
  userName?: string | null
): Promise<{ reply: string; source: string }> {
  const res = await safeFetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, history, userEmail, userName }),
  });

  const data = await safeParseJson<{ reply: string; source: string; success?: boolean; error?: string }>(
    res,
    'Failed to reach AI assistant'
  );
  if (data.success === false) throw new Error(data.error || 'Failed to reach AI assistant');
  return data;
}

// ==========================================
// Module 6: AI Price Estimation
// ==========================================
export interface PriceEstimateData {
  sufficientData: boolean;
  message?: string;
  resaleRange: { min: number; max: number; currency: string } | null;
  repairRange: { min: number; max: number; currency: string } | null;
  scrapValueRange: { min: number; max: number; currency: string } | null;
  assumptions: string[];
  disclaimer: string;
  pricingDate: string;
  source?: string;
}

export async function fetchPriceEstimate(deviceData: {
  category: string;
  brand?: string;
  model?: string;
  age?: number;
  condition?: string;
  working?: boolean;
  powersOn?: boolean;
  damage?: string;
}): Promise<PriceEstimateData> {
  const res = await safeFetch('/api/estimate-price', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(deviceData),
  });

  const data = await safeParseJson<PriceEstimateData & { success?: boolean; error?: string }>(
    res,
    'Failed to estimate price'
  );
  if (data.success === false) throw new Error(data.error || 'Failed to estimate price');
  return data;
}

// ==========================================
// Module 5: Partner Matching
// ==========================================
export interface PartnerMatchItem {
  partner: PartnerItem;
  matchScore: number;
  reasons: string[];
  remainingSlots: number;
  isRealProvider: boolean;
  breakdown: {
    categoryCompatibility: number;
    locationProximity: number;
    capacityAvailability: number;
    specializationAlignment: number;
    verificationStatus: number;
  };
}

export interface PartnerMatchResponse {
  safetyBlocked: boolean;
  reason?: string;
  eligiblePartners: PartnerMatchItem[];
  ineligibleCount: number;
  totalMatches: number;
}

export async function fetchPartnerMatches(criteria: {
  category: string;
  action: 'repair' | 'donate' | 'recycle';
  locality?: string;
  pincode?: string;
  unsafe?: boolean;
}): Promise<PartnerMatchResponse> {
  const res = await safeFetch('/api/partners/match', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(criteria),
  });

  const data = await safeParseJson<PartnerMatchResponse & { success?: boolean; error?: string }>(
    res,
    'Partner matching failed'
  );
  if (data.success === false) throw new Error(data.error || 'Partner matching failed');
  return data;
}

