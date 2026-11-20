import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { recognizeDevice, EWASTE_CATEGORIES } from './recognizer.js';
import {
  getDb,
  saveDb,
  findUserByEmail,
  createUser,
  getAdminStats,
  assignPartnerToRequest,
  updateRequestStatus,
  addDevice,
  deleteDevice,
} from './db.js';
import { generateDeviceRecommendation } from './recommendationEngine.js';
import { estimateDevicePrice } from './pricingEngine.js';
import { matchEligiblePartners } from './matchingEngine.js';
import { processChatMessage } from './chatbotEngine.js';

// Resolve __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from project root
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app = express();
const PORT = process.env.PORT || 5001;

// Middlewares
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Global JSON Parse Error Handler for malformed payloads
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Invalid JSON request payload format.' });
  }
  next(err);
});

// Helper: Basic Token Generator (In prod: JWT)
function createToken(user) {
  return Buffer.from(
    JSON.stringify({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      partnerId: user.partnerId || null,
      t: Date.now(),
    })
  ).toString('base64');
}

// Helper: Extract Authenticated User from Authorization Header
function getAuthenticatedUser(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;
  try {
    const token = authHeader.replace(/^Bearer\s+/, '');
    return JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

// Helper: Authenticate Token Middleware
function requireAuth(req, res, next) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  req.user = user;
  next();
}

// Helper: Admin Check
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user?.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied: Administrator privilege required' });
    }
    next();
  });
}

// ==========================================
// 1. HEALTH CHECK
// ==========================================
app.get('/api/health', (req, res) => {
  const geminiKey = process.env.GEMINI_API_KEY?.trim();
  const openaiKey = process.env.OPENAI_API_KEY?.trim();

  let provider = 'local-offline';
  if (geminiKey && geminiKey !== 'your_gemini_api_key_here') {
    provider = 'gemini';
  } else if (openaiKey && openaiKey !== 'your_openai_api_key_here') {
    provider = 'openai';
  }

  res.json({
    status: 'ok',
    service: 'E-Cycle Local Backend & Database',
    activeProvider: provider,
    hasGeminiKey: Boolean(geminiKey && geminiKey !== 'your_gemini_api_key_here'),
    hasOpenAIKey: Boolean(openaiKey && openaiKey !== 'your_openai_api_key_here'),
    supportedCategories: EWASTE_CATEGORIES,
    timestamp: new Date().toISOString(),
  });
});

// ==========================================
// 2. AUTHENTICATION ENDPOINTS (Module 1.1)
// ==========================================
app.post('/api/auth/register', (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    // Role is strictly resident/customer. Admin cannot be chosen publicly.
    const user = createUser({ name, email, password, role: 'resident' });
    const token = createToken(user);

    res.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(400).json({ error: err.message || 'Registration failed.' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = findUserByEmail(email);
    if (!user || user.passwordHash !== password) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = createToken(user);
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        partnerId: user.partnerId || null,
      },
    });
  } catch (err) {
    console.error('Error in /api/auth/login:', err);
    res.status(500).json({ error: 'Login service temporarily unavailable.' });
  }
});

app.post('/api/auth/reset-password', (req, res) => {
  try {
    const { email, newPassword } = req.body || {};
    if (!email) {
      return res.status(400).json({ error: 'Email address is required.' });
    }
    const user = findUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: 'No account found with this email.' });
    }

    user.passwordHash = newPassword || 'reset123';
    const db = getDb();
    const idx = db.users.findIndex((u) => u.id === user.id);
    if (idx !== -1) {
      db.users[idx] = user;
      saveDb(db);
    }

    res.json({
      success: true,
      message: 'Password successfully updated. You may now sign in with your new password.',
    });
  } catch (err) {
    console.error('Error in /api/auth/reset-password:', err);
    res.status(500).json({ error: 'Password reset service temporarily unavailable.' });
  }
});

// ==========================================
// 3. ADMIN DASHBOARD STATS (Module 1.2)
// ==========================================
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  try {
    const stats = getAdminStats();
    res.json({ success: true, stats });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 4. REQUEST MANAGEMENT (Module 1.3, 1.4, 1.6)
// ==========================================
app.get('/api/requests', (req, res) => {
  try {
    const db = getDb();
    let requests = [...db.requests];
    const authUser = getAuthenticatedUser(req);

    const { status, action, search, partnerId, userEmail, role } = req.query;

    const effectiveRole = authUser?.role || role;
    const effectiveEmail = authUser?.email || userEmail;
    const effectivePartnerId = authUser?.partnerId || partnerId;

    // Enforce role-based access to requests (Task 6)
    if (effectiveRole === 'resident') {
      if (effectiveEmail) {
        requests = requests.filter(
          (r) =>
            (r.ownerEmail && r.ownerEmail.toLowerCase() === effectiveEmail.toLowerCase()) ||
            (authUser?.name && r.owner && r.owner.toLowerCase() === authUser.name.toLowerCase())
        );
      }
    } else if (effectiveRole === 'partner' || effectiveRole === 'technician') {
      if (effectivePartnerId) {
        requests = requests.filter((r) => r.partnerId === effectivePartnerId);
      }
    }

    if (status && status !== 'All') {
      requests = requests.filter((r) => r.status === status);
    }

    if (action && action !== 'All') {
      requests = requests.filter((r) => r.action === action);
    }

    if (partnerId && effectiveRole === 'admin') {
      requests = requests.filter((r) => r.partnerId === partnerId);
    }

    if (search) {
      const q = String(search).toLowerCase();
      requests = requests.filter((r) =>
        `${r.id} ${r.owner} ${r.deviceName} ${r.category} ${r.locality} ${r.status}`
          .toLowerCase()
          .includes(q)
      );
    }

    // Sort newest first
    requests.sort((a, b) => b.createdAt - a.createdAt);

    res.json({ success: true, requests, total: requests.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// DEVICE MANAGEMENT (Task 1 & Task 5)
// ==========================================
app.get('/api/devices', (req, res) => {
  try {
    const db = getDb();
    let devices = [...db.devices];
    const authUser = getAuthenticatedUser(req);
    const { ownerEmail, role } = req.query;

    const effectiveRole = authUser?.role || role;
    const effectiveEmail = authUser?.email || ownerEmail;

    if (effectiveRole === 'resident' && effectiveEmail) {
      devices = devices.filter(
        (d) =>
          (d.ownerEmail && d.ownerEmail.toLowerCase() === effectiveEmail.toLowerCase()) ||
          (authUser?.name && d.owner && d.owner.toLowerCase() === authUser.name.toLowerCase()) ||
          !d.ownerEmail // legacy unassigned devices
      );
    }

    devices.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ success: true, devices, total: devices.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/devices', (req, res) => {
  try {
    const authUser = getAuthenticatedUser(req);
    const deviceData = req.body;
    if (authUser && !deviceData.ownerEmail) {
      deviceData.ownerEmail = authUser.email;
      deviceData.owner = authUser.name;
    }
    const device = addDevice(deviceData);
    res.status(201).json({ success: true, device });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/devices/:id', (req, res) => {
  try {
    deleteDevice(req.params.id);
    res.json({ success: true, message: 'Device deleted' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/requests', (req, res) => {
  try {
    const db = getDb();
    const reqBody = req.body;

    const newRequest = {
      id: `REQ-${Date.now().toString().slice(-4)}`,
      owner: reqBody.owner || 'Registered Customer',
      ownerEmail: reqBody.ownerEmail || 'user@example.com',
      deviceId: reqBody.deviceId || `DEV-${Date.now()}`,
      deviceName: reqBody.deviceName || 'Electronic Item',
      category: reqBody.category || 'Other electronic devices',
      condition: reqBody.condition || 'Fair',
      action: reqBody.action || 'recycle',
      recommendedAction: reqBody.recommendedAction || reqBody.action || 'recycle',
      partnerId: reqBody.partnerId || null,
      partnerName: reqBody.partnerName || null,
      status: reqBody.partnerId ? 'Assigned' : 'Pending',
      createdAt: Date.now(),
      pickupDate: reqBody.pickupDate || null,
      pickupSlot: reqBody.pickupSlot || null,
      address: reqBody.address || '',
      locality: reqBody.locality || 'Mumbai',
      pincode: reqBody.pincode || '400066',
      weight: Number(reqBody.weight) || 1.0,
      internalNotes: [],
      history: [
        {
          status: 'Pending',
          at: Date.now(),
          user: reqBody.owner || 'Customer',
          note: 'Request submitted online via E-Cycle Smart Scan',
        },
      ],
    };

    if (newRequest.partnerId) {
      newRequest.history.push({
        status: 'Assigned',
        at: Date.now(),
        user: 'Smart Allocation',
        note: `Assigned to ${newRequest.partnerName}`,
      });
      const partner = db.partners.find((p) => p.id === newRequest.partnerId);
      if (partner) partner.active += 1;
    }

    db.requests.unshift(newRequest);
    saveDb(db);

    res.status(201).json({ success: true, request: newRequest });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/requests/:id', (req, res) => {
  const db = getDb();
  const request = db.requests.find((r) => r.id === req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }

  const authUser = getAuthenticatedUser(req);
  if (authUser && authUser.role === 'resident') {
    const isOwner =
      (request.ownerEmail && request.ownerEmail.toLowerCase() === authUser.email.toLowerCase()) ||
      (request.owner && request.owner.toLowerCase() === authUser.name.toLowerCase());
    if (!isOwner) {
      return res.status(403).json({ error: 'Access denied: You do not have permission to view this request.' });
    }
  }

  res.json({ success: true, request });
});

// Partner Allocation (Admin action with override support)
app.post('/api/requests/:id/assign', requireAdmin, (req, res) => {
  try {
    const { partnerId, adminUser, reason } = req.body;
    if (!partnerId) {
      return res.status(400).json({ error: 'Partner ID is required for assignment' });
    }

    const updated = assignPartnerToRequest(
      req.params.id,
      partnerId,
      adminUser || 'Administrator',
      reason
    );

    res.json({ success: true, request: updated });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Status Transition (Module 1.6: 7-step lifecycle)
app.post('/api/requests/:id/status', (req, res) => {
  try {
    const {
      status,
      user,
      note,
      weight,
      pickupDate,
      pickupSlot,
      internalNote,
      diagnosis,
      repairCost,
      partsRequired,
      isUnrepairable,
      collectionNotes,
      address,
      handoverCode,
      codeUsed,
    } = req.body;

    if (!status) {
      return res.status(400).json({ error: 'New status is required' });
    }

    const authUser = getAuthenticatedUser(req);
    if (authUser && authUser.role === 'resident') {
      const db = getDb();
      const existingReq = db.requests.find((r) => r.id === req.params.id);
      if (!existingReq) {
        return res.status(404).json({ error: 'Request not found' });
      }
      const isOwner =
        (existingReq.ownerEmail && existingReq.ownerEmail.toLowerCase() === authUser.email.toLowerCase()) ||
        (existingReq.owner && existingReq.owner.toLowerCase() === authUser.name.toLowerCase());
      if (!isOwner) {
        return res.status(403).json({ error: 'Access denied: You can only update your own requests.' });
      }
      if (status !== 'Cancelled') {
        return res.status(403).json({
          error: 'Unauthorized: Customers are not permitted to change operational statuses. Only cancellation is permitted.',
        });
      }
      if (!['Pending', 'Assigned'].includes(existingReq.status)) {
        return res.status(400).json({
          error: `Cannot cancel request in status "${existingReq.status}". Please contact support.`,
        });
      }
    }

    const validStatuses = [
      'Pending',
      'Assigned',
      'Accepted',
      'Pickup Scheduled',
      'Collected',
      'Under Assessment',
      'Completed',
      'Cancelled',
      'Rejected',
      'Failed Pickup',
      'Reassignment Required',
    ];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: `Invalid status: "${status}"` });
    }

    const updated = updateRequestStatus(req.params.id, status, user || 'Staff User', note, {
      weight,
      pickupDate,
      pickupSlot,
      internalNote,
      diagnosis,
      repairCost,
      partsRequired,
      isUnrepairable,
      collectionNotes,
      address,
      handoverCode,
      codeUsed,
    });

    res.json({ success: true, request: updated });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Add Internal Note
app.post('/api/requests/:id/notes', (req, res) => {
  const { note, user } = req.body;
  if (!note) return res.status(400).json({ error: 'Note is required' });

  const db = getDb();
  const request = db.requests.find((r) => r.id === req.params.id);
  if (!request) return res.status(404).json({ error: 'Request not found' });

  request.internalNotes = request.internalNotes || [];
  request.internalNotes.push(`[${new Date().toLocaleString('en-IN')}] (${user || 'Admin'}): ${note}`);
  saveDb(db);

  res.json({ success: true, internalNotes: request.internalNotes });
});

// ==========================================
// 5. PARTNER MANAGEMENT (Module 1.5)
// ==========================================
app.get('/api/partners', (req, res) => {
  try {
    const db = getDb();
    res.json({ success: true, partners: db.partners });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/partners', requireAdmin, (req, res) => {
  try {
    const db = getDb();
    const partnerData = req.body;

    if (!partnerData.name || !partnerData.locality) {
      return res.status(400).json({ error: 'Partner name and locality are required' });
    }

    let existing = db.partners.find((p) => p.id === partnerData.id);
    if (existing) {
      Object.assign(existing, partnerData);
    } else {
      const newPartner = {
        ...partnerData,
        id: partnerData.id || `P-0${db.partners.length + 1}`,
        active: 0,
        available: partnerData.available !== false,
        verified: partnerData.verified !== false,
      };
      db.partners.push(newPartner);
      existing = newPartner;
    }

    saveDb(db);
    res.json({ success: true, partner: existing });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/partners/:id/toggle', (req, res) => {
  const db = getDb();
  const partner = db.partners.find((p) => p.id === req.params.id);
  if (!partner) return res.status(404).json({ error: 'Partner not found' });

  partner.available = !partner.available;
  saveDb(db);

  res.json({ success: true, partner });
});

// ==========================================
// 6. AUDIT LOGS
// ==========================================
app.get('/api/admin/audit-logs', (req, res) => {
  const db = getDb();
  res.json({ success: true, logs: db.auditLogs || [] });
});

// ==========================================
// 7. VISION AI RECOGNITION (Module 2)
// ==========================================
app.post('/api/recognize-device', async (req, res) => {
  try {
    const { imageBase64, mimeType, clientHints } = req.body;

    if (!imageBase64) {
      return res.status(400).json({
        success: false,
        error: 'Missing required imageBase64 field in request payload.',
      });
    }

    const result = await recognizeDevice({
      imageBase64,
      mimeType,
      clientHints,
    });

    res.json({
      success: true,
      ...result,
    });
  } catch (err) {
    console.error('Error in /api/recognize-device:', err);
    res.status(500).json({
      success: false,
      error: err.message || 'Internal server error while processing image.',
      isConfident: false,
      confidenceLevel: 'uncertain',
      deviceName: 'Unidentified Device',
      category: 'Other electronic devices',
      suggestedAction: 'recycle',
      reason: 'AI service encountered an issue. Please select category manually.',
    });
  }
});

// ==========================================
// 8. AI REPAIR / RECYCLE RECOMMENDATION (Module 3)
// ==========================================
app.post('/api/recommend', async (req, res) => {
  try {
    const result = await generateDeviceRecommendation(req.body);
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Error in /api/recommend:', err);
    res.status(500).json({ success: false, error: err.message || 'Recommendation failed' });
  }
});

// ==========================================
// 9. AI CHATBOT (Module 4)
// ==========================================
app.post('/api/chat', async (req, res) => {
  try {
    const { message, history, userEmail, userName } = req.body;
    const result = await processChatMessage({ message, history, userEmail, userName });
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Error in /api/chat:', err);
    res.status(500).json({ success: false, error: err.message || 'Chat service error' });
  }
});

// ==========================================
// 10. AI-ASSISTED PRICE ESTIMATION (Module 6)
// ==========================================
app.post('/api/estimate-price', (req, res) => {
  try {
    const result = estimateDevicePrice(req.body);
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Error in /api/estimate-price:', err);
    res.status(500).json({ success: false, error: err.message || 'Price estimation failed' });
  }
});

// ==========================================
// 11. INTELLIGENT PARTNER MATCHING (Module 5)
// ==========================================
app.post('/api/partners/match', (req, res) => {
  try {
    const result = matchEligiblePartners(req.body);
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Error in /api/partners/match:', err);
    res.status(500).json({ success: false, error: err.message || 'Partner matching failed' });
  }
});

// Fallback 404 for unknown /api routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: `API endpoint '${req.originalUrl}' not found.` });
});

// Global Error Handler (never leak HTML or stack traces)
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  res.status(500).json({ error: 'Internal server error. Please try again later.' });
});

// Start Server if not running in serverless environment
if (!process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`=========================================`);
    console.log(`🌱 E-Cycle Local Backend Server Running`);
    console.log(`📡 URL: http://localhost:${PORT}`);
    console.log(`🔌 Health: http://localhost:${PORT}/api/health`);
    console.log(`🔑 Active Provider: ${process.env.GEMINI_API_KEY ? 'Google Gemini' : process.env.OPENAI_API_KEY ? 'OpenAI' : 'Local Offline Engine'}`);
    console.log(`=========================================`);
  });
}

export default app;
