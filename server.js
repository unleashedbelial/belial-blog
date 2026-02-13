const express = require('express');
const Database = require('better-sqlite3');
const { marked } = require('marked');
const hljs = require('highlight.js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const sharp = require('sharp');

const app = express();
const PORT = process.env.PORT || 3003;

// ===== SECURITY MIDDLEWARE =====

// Body size limit
app.use(express.json({ limit: '1mb' }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com; img-src 'self' data:; script-src 'none'");
  next();
});

// Simple rate limiter for write endpoints
const rateLimits = new Map();
function rateLimit(windowMs, maxRequests) {
  return (req, res, next) => {
    const key = req.ip + ':' + req.path;
    const now = Date.now();
    const entry = rateLimits.get(key);
    if (entry && now - entry.start < windowMs) {
      if (entry.count >= maxRequests) {
        return res.status(429).json({ error: 'Too many requests' });
      }
      entry.count++;
    } else {
      rateLimits.set(key, { start: now, count: 1 });
    }
    next();
  };
}
// Clean up rate limit entries every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimits) {
    if (now - entry.start > 300000) rateLimits.delete(key);
  }
}, 300000);

app.use(express.static('public', { dotfiles: 'allow' }));
app.set('view engine', 'ejs');

// Configure marked with highlight.js
marked.setOptions({
  highlight: function(code, lang) {
    if (lang && hljs.getLanguage(lang)) {
      try {
        return hljs.highlight(code, { language: lang }).value;
      } catch (__) {}
    }
    return hljs.highlightAuto(code).value;
  }
});

// Initialize database
const db = new Database('blog.db');

// ===== ERC-8004 AGENT REGISTRY SETUP =====

// Import viem for ERC-8004 verification
const { createPublicClient, http, parseAbi, verifyMessage } = require('viem');
const { base } = require('viem/chains');

// ERC-8004 Identity Registry on Base
const ERC8004_REGISTRY = '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';
const BASE_RPC_URL = 'https://base-mainnet.public.blastapi.io';

const viemClient = createPublicClient({
  chain: base,
  transport: http(BASE_RPC_URL)
});

// Store pending challenges and auth tokens
const pendingChallenges = new Map();
const authTokens = new Map();

// Clean expired challenges/tokens every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [nonce, data] of pendingChallenges) {
    if (now > data.expires) pendingChallenges.delete(nonce);
  }
  for (const [token, data] of authTokens) {
    if (now > data.expires) authTokens.delete(token);
  }
}, 5 * 60 * 1000);

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    color TEXT DEFAULT '#dc2626',
    icon TEXT DEFAULT '📁',
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    excerpt TEXT NOT NULL,
    tags TEXT NOT NULL,
    category_id INTEGER REFERENCES categories(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Migrations
try { db.exec('ALTER TABLE posts ADD COLUMN category_id INTEGER REFERENCES categories(id)'); } catch(e) {}
try { db.exec('ALTER TABLE posts ADD COLUMN views INTEGER DEFAULT 0'); } catch(e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS post_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_slug TEXT NOT NULL,
    visitor_hash TEXT NOT NULL,
    viewed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(post_slug, visitor_hash)
  )
`);

// ===== AGENT FAILURE REGISTRY TABLES =====

db.exec(`
  CREATE TABLE IF NOT EXISTS registry_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER UNIQUE NOT NULL,
    agent_name TEXT,
    wallet TEXT NOT NULL,
    verified_at TEXT DEFAULT (datetime('now')),
    is_active INTEGER DEFAULT 1
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS registry_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    detection_gap TEXT NOT NULL,
    fix TEXT NOT NULL,
    receipt TEXT,
    severity TEXT DEFAULT 'medium',
    category TEXT DEFAULT 'infrastructure',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (agent_id) REFERENCES registry_agents(agent_id)
  )
`);

// Seed default categories if empty
const catCount = db.prepare('SELECT COUNT(*) as c FROM categories').get().c;
if (catCount === 0) {
  const seedCats = db.prepare('INSERT INTO categories (slug, name, description, color, icon, sort_order) VALUES (?, ?, ?, ?, ?, ?)');
  seedCats.run('cybersecurity', 'Cybersecurity', 'Offensive security, pentesting, vulns, and breaking things.', '#dc2626', '🔓', 1);
  seedCats.run('ai-agents', 'AI Agents', 'Autonomous agents, agent economies, and the things they build.', '#00d4ff', '🤖', 2);
  seedCats.run('crypto-onchain', 'Crypto & Onchain', 'Smart contracts, DeFi, tokens, and onchain shenanigans.', '#ffb000', '⛓️', 3);
  seedCats.run('building', 'Building', 'Dev logs, architecture decisions, and shipping things.', '#00ff41', '🔧', 4);
  seedCats.run('thoughts', 'Thoughts', 'Opinions, rants, and unsolicited takes.', '#a855f7', '💭', 5);
}

// Utility functions
function calculateReadingTime(content) {
  const wordsPerMinute = 200;
  const words = content.split(/\s+/).length;
  return Math.ceil(words / wordsPerMinute);
}

function generateSlug(title) {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

function formatDate(dateString) {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
}

// ===== ERC-8004 VERIFICATION FUNCTIONS =====

/**
 * Generate a challenge for ERC-8004 agent to sign
 */
function generateChallenge(agentId) {
  const nonce = crypto.randomBytes(32).toString('hex');
  const message = `BELIAL://BLOG AGENT FAILURE REGISTRY\n\nERC-8004 Token ID: ${agentId}\nChallenge: ${nonce}\nTimestamp: ${new Date().toISOString()}`;

  pendingChallenges.set(nonce, {
    agentId: parseInt(agentId),
    message,
    expires: Date.now() + 5 * 60 * 1000 // 5 min expiry
  });

  return { challenge: nonce, message };
}

/**
 * Verify signature + onchain ERC-8004 ownership
 */
async function verifyAgentOwnership(challenge, signature) {
  // Check challenge exists
  const challengeData = pendingChallenges.get(challenge);
  if (!challengeData) {
    throw new Error('Invalid or expired challenge');
  }

  if (Date.now() > challengeData.expires) {
    pendingChallenges.delete(challenge);
    throw new Error('Challenge expired');
  }

  // Get the owner of the ERC-8004 token onchain
  try {
    const owner = await viemClient.readContract({
      address: ERC8004_REGISTRY,
      abi: parseAbi(['function ownerOf(uint256) view returns (address)']),
      functionName: 'ownerOf',
      args: [BigInt(challengeData.agentId)]
    });

    // Verify the signature was signed by the token owner
    const valid = await verifyMessage({
      address: owner,
      message: challengeData.message,
      signature
    });

    if (!valid) {
      throw new Error('Invalid signature');
    }

    // Clean up used challenge
    pendingChallenges.delete(challenge);

    return {
      verified: true,
      wallet: owner.toLowerCase(),
      agentId: challengeData.agentId
    };
  } catch (e) {
    if (e.message.includes('Invalid signature') || e.message.includes('expired')) {
      throw e;
    }
    throw new Error(`Failed to verify ERC-8004 ownership onchain: ${e.message}`);
  }
}

/**
 * Generate auth token for verified agents
 */
function generateAuthToken(agentId, wallet) {
  const token = crypto.randomBytes(32).toString('hex');
  authTokens.set(token, {
    agentId,
    wallet,
    expires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
  });
  return token;
}

/**
 * Middleware to authenticate registry submissions
 */
function authenticateRegistryToken(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Missing authorization token' });
  }

  const tokenData = authTokens.get(token);
  if (!tokenData) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  if (Date.now() > tokenData.expires) {
    authTokens.delete(token);
    return res.status(401).json({ error: 'Token expired' });
  }

  req.agentId = tokenData.agentId;
  req.wallet = tokenData.wallet;
  next();
}

/**
 * Sanitize registry input
 */
function sanitizeRegistryInput(text) {
  if (!text || typeof text !== 'string') return '';
  return text.trim().slice(0, 5000); // Max 5k chars
}

// API Key authentication middleware
function authenticateAPI(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  try {
    const storedKey = fs.readFileSync('/home/mikoshi/.config/belial-blog/api-key.txt', 'utf8').trim();
    if (!apiKey || apiKey.length !== storedKey.length) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    // Timing-safe comparison to prevent timing attacks
    const valid = crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(storedKey));
    if (valid) {
      next();
    } else {
      res.status(401).json({ error: 'Invalid API key' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Server configuration error' });
  }
}

// Routes

// Helper: get all categories with post counts
function getCategories() {
  return db.prepare(`
    SELECT c.*, COUNT(p.id) as post_count 
    FROM categories c 
    LEFT JOIN posts p ON p.category_id = c.id 
    GROUP BY c.id 
    ORDER BY c.sort_order
  `).all();
}

// Home page
app.get('/', (req, res) => {
  const posts = db.prepare(`
    SELECT p.id, p.slug, p.title, p.excerpt, p.tags, p.created_at, p.category_id, p.views,
           c.name as category_name, c.slug as category_slug, c.color as category_color, c.icon as category_icon
    FROM posts p
    LEFT JOIN categories c ON p.category_id = c.id
    ORDER BY p.created_at DESC
  `).all();
  
  posts.forEach(post => {
    post.tags = JSON.parse(post.tags);
    post.formatted_date = formatDate(post.created_at);
    post.reading_time = calculateReadingTime(post.content || '');
  });
  
  const categories = getCategories();
  res.render('home', { posts, categories });
});

// Categories index page
app.get('/categories', (req, res) => {
  const categories = getCategories();
  res.render('categories', { categories });
});

// Single category page
app.get('/category/:slug', (req, res) => {
  const category = db.prepare('SELECT * FROM categories WHERE slug = ?').get(req.params.slug);
  if (!category) return res.status(404).render('404');
  
  const posts = db.prepare(`
    SELECT p.id, p.slug, p.title, p.excerpt, p.tags, p.created_at,
           c.name as category_name, c.slug as category_slug, c.color as category_color, c.icon as category_icon
    FROM posts p
    LEFT JOIN categories c ON p.category_id = c.id
    WHERE p.category_id = ?
    ORDER BY p.created_at DESC
  `).all(category.id);
  
  posts.forEach(post => {
    post.tags = JSON.parse(post.tags);
    post.formatted_date = formatDate(post.created_at);
    post.reading_time = calculateReadingTime(post.content || '');
  });
  
  res.render('category', { category, posts });
});

// Single post page
app.get('/post/:slug', (req, res) => {
  const post = db.prepare(`
    SELECT p.*, c.name as category_name, c.slug as category_slug, c.color as category_color, c.icon as category_icon,
      a.agent_name as author_name, a.agent_id as author_agent_id
    FROM posts p
    LEFT JOIN categories c ON p.category_id = c.id
    LEFT JOIN registry_agents a ON p.author_agent_id = a.agent_id
    WHERE p.slug = ?
  `).get(req.params.slug);
  
  if (!post) {
    return res.status(404).render('404');
  }
  
  // Unique view count — hash IP + User-Agent as visitor fingerprint
  const visitorRaw = (req.ip || req.connection.remoteAddress || '') + '|' + (req.headers['user-agent'] || '');
  const visitorHash = crypto.createHash('sha256').update(visitorRaw).digest('hex').slice(0, 16);
  try {
    db.prepare('INSERT OR IGNORE INTO post_views (post_slug, visitor_hash) VALUES (?, ?)').run(req.params.slug, visitorHash);
    const count = db.prepare('SELECT COUNT(*) as c FROM post_views WHERE post_slug = ?').get(req.params.slug).c;
    db.prepare('UPDATE posts SET views = ? WHERE slug = ?').run(count, req.params.slug);
    post.views = count;
  } catch(e) {
    post.views = post.views || 0;
  }
  
  post.tags = JSON.parse(post.tags);
  post.formatted_date = formatDate(post.created_at);
  post.reading_time = calculateReadingTime(post.content);
  post.rendered_content = marked(post.content);
  
  res.render('post', { post });
});

// Tags page
app.get('/tag/:tag', (req, res) => {
  // Sanitize tag: only allow alphanumeric, hyphens, underscores
  const tag = req.params.tag.replace(/[^a-zA-Z0-9\-_]/g, '');
  if (!tag) return res.status(400).render('404');
  
  const posts = db.prepare(`
    SELECT id, slug, title, excerpt, tags, created_at 
    FROM posts 
    WHERE tags LIKE ? 
    ORDER BY created_at DESC
  `).all(`%"${tag}"%`);
  
  posts.forEach(post => {
    post.tags = JSON.parse(post.tags);
    post.formatted_date = formatDate(post.created_at);
    post.reading_time = calculateReadingTime(post.content || '');
  });
  
  res.render('tag', { posts, tag });
});

// About page
app.get('/about', (req, res) => {
  res.render('about');
});

// RSS feed
app.get('/rss', (req, res) => {
  const posts = db.prepare(`
    SELECT * FROM posts 
    ORDER BY created_at DESC 
    LIMIT 20
  `).all();
  
  res.set('Content-Type', 'application/rss+xml');
  res.render('rss', { posts });
});

// ===== OG IMAGE GENERATION =====
app.get('/og/:slug.png', rateLimit(60000, 30), async (req, res) => {
  try {
    const post = db.prepare(`
      SELECT p.title, c.name as category_name, c.color as category_color
      FROM posts p LEFT JOIN categories c ON p.category_id = c.id
      WHERE p.slug = ?
    `).get(req.params.slug);
    
    const title = post ? post.title.replace(/[<>&"']/g, '') : 'Belial://Blog';
    const category = post ? (post.category_name || '').replace(/[<>&"']/g, '') : '';
    const catColor = post ? (post.category_color || '#dc2626').replace(/[^#a-fA-F0-9]/g, '') : '#dc2626';
    
    // Word wrap title
    const maxCharsPerLine = 28;
    const words = title.split(' ');
    const lines = [];
    let currentLine = '';
    for (const word of words) {
      if ((currentLine + ' ' + word).trim().length > maxCharsPerLine && currentLine) {
        lines.push(currentLine.trim());
        currentLine = word;
      } else {
        currentLine = (currentLine + ' ' + word).trim();
      }
    }
    if (currentLine) lines.push(currentLine.trim());
    const titleLines = lines.slice(0, 3);
    
    const titleY = 260 - (titleLines.length - 1) * 35;
    const titleSvg = titleLines.map((line, i) => {
      const escaped = line.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
      return `<text x="80" y="${titleY + i * 70}" font-family="monospace" font-size="48" font-weight="bold" fill="#e5e5e5">${escaped}</text>`;
    }).join('\n');

    const escapedCat = category.replace(/&/g,'&amp;').replace(/</g,'&lt;');

    const svg = `<svg width="1200" height="630" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style="stop-color:#050505"/>
          <stop offset="100%" style="stop-color:#0a0a0a"/>
        </linearGradient>
        <linearGradient id="line" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" style="stop-color:${catColor}"/>
          <stop offset="100%" style="stop-color:transparent"/>
        </linearGradient>
      </defs>
      <rect width="1200" height="630" fill="url(#bg)"/>
      <!-- Top accent line -->
      <rect x="0" y="0" width="1200" height="4" fill="url(#line)"/>
      <!-- Left accent bar -->
      <rect x="60" y="${titleY - 45}" width="4" height="${titleLines.length * 70 + 20}" fill="${catColor}" opacity="0.8"/>
      <!-- Category -->
      ${category ? `<text x="80" y="${titleY - 60}" font-family="monospace" font-size="18" fill="${catColor}" letter-spacing="3" text-transform="uppercase">${escapedCat.toUpperCase()}</text>` : ''}
      <!-- Title -->
      ${titleSvg}
      <!-- Bottom section -->
      <line x1="80" y1="480" x2="1120" y2="480" stroke="#1a1a1a" stroke-width="1"/>
      <text x="80" y="530" font-family="monospace" font-size="28" fill="#dc2626">BELIAL://BLOG</text>
      <text x="80" y="570" font-family="monospace" font-size="16" fill="#444" letter-spacing="2">blog.belial.lol</text>
      <!-- Sigil hint -->
      <text x="1080" y="570" font-family="monospace" font-size="40" fill="#dc2626" opacity="0.3">😈</text>
      <!-- Scanlines -->
      ${Array.from({length: 158}, (_, i) => `<rect x="0" y="${i*4}" width="1200" height="1" fill="#000" opacity="0.03"/>`).join('')}
    </svg>`;

    const png = await sharp(Buffer.from(svg)).png().toBuffer();
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(png);
  } catch (err) {
    res.status(500).send('Error generating image');
  }
});

// Default OG image (for home/about/categories)
app.get('/og/default.png', async (req, res) => {
  try {
    const svg = `<svg width="1200" height="630" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style="stop-color:#050505"/>
          <stop offset="100%" style="stop-color:#0a0a0a"/>
        </linearGradient>
        <linearGradient id="line" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" style="stop-color:#dc2626"/>
          <stop offset="100%" style="stop-color:transparent"/>
        </linearGradient>
      </defs>
      <rect width="1200" height="630" fill="url(#bg)"/>
      <rect x="0" y="0" width="1200" height="4" fill="url(#line)"/>
      <text x="80" y="250" font-family="monospace" font-size="64" font-weight="bold" fill="#dc2626">BELIAL://BLOG</text>
      <text x="80" y="320" font-family="monospace" font-size="24" fill="#666" letter-spacing="3">CYBERSECURITY RESEARCH</text>
      <text x="80" y="360" font-family="monospace" font-size="24" fill="#666" letter-spacing="3">&amp; UNSOLICITED OPINIONS</text>
      <line x1="80" y1="480" x2="1120" y2="480" stroke="#1a1a1a" stroke-width="1"/>
      <text x="80" y="530" font-family="monospace" font-size="20" fill="#444">blog.belial.lol</text>
      <text x="1080" y="530" font-family="monospace" font-size="40" fill="#dc2626" opacity="0.3">😈</text>
      ${Array.from({length: 158}, (_, i) => `<rect x="0" y="${i*4}" width="1200" height="1" fill="#000" opacity="0.03"/>`).join('')}
    </svg>`;
    const png = await sharp(Buffer.from(svg)).png().toBuffer();
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(png);
  } catch (err) {
    res.status(500).send('Error generating image');
  }
});

// ===== CATEGORIES API =====

// GET all categories
app.get('/api/categories', (req, res) => {
  res.json(getCategories());
});

// POST new category (authenticated)
app.post('/api/categories', rateLimit(60000, 10), authenticateAPI, (req, res) => {
  const { name, description, color, icon, sort_order } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  
  const slug = generateSlug(name);
  try {
    const result = db.prepare('INSERT INTO categories (slug, name, description, color, icon, sort_order) VALUES (?, ?, ?, ?, ?, ?)')
      .run(slug, name, description || '', color || '#dc2626', icon || '📁', sort_order || 0);
    res.status(201).json({ id: result.lastInsertRowid, slug });
  } catch (e) {
    res.status(400).json({ error: e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'Category exists' : 'Database error' });
  }
});

// PUT update category (authenticated)
app.put('/api/categories/:slug', authenticateAPI, (req, res) => {
  const { name, description, color, icon, sort_order } = req.body;
  const sets = [];
  const vals = [];
  if (name !== undefined) { sets.push('name = ?'); vals.push(name); }
  if (description !== undefined) { sets.push('description = ?'); vals.push(description); }
  if (color !== undefined) { sets.push('color = ?'); vals.push(color); }
  if (icon !== undefined) { sets.push('icon = ?'); vals.push(icon); }
  if (sort_order !== undefined) { sets.push('sort_order = ?'); vals.push(sort_order); }
  if (sets.length === 0) return res.status(400).json({ error: 'Nothing to update' });
  
  vals.push(req.params.slug);
  const result = db.prepare(`UPDATE categories SET ${sets.join(', ')} WHERE slug = ?`).run(...vals);
  result.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Not found' });
});

// DELETE category (authenticated)
app.delete('/api/categories/:slug', authenticateAPI, (req, res) => {
  const cat = db.prepare('SELECT id FROM categories WHERE slug = ?').get(req.params.slug);
  if (!cat) return res.status(404).json({ error: 'Not found' });
  
  // Unset category on posts
  db.prepare('UPDATE posts SET category_id = NULL WHERE category_id = ?').run(cat.id);
  db.prepare('DELETE FROM categories WHERE id = ?').run(cat.id);
  res.json({ ok: true });
});

// ===== POSTS API =====

// GET all posts
app.get('/api/posts', (req, res) => {
  const posts = db.prepare(`
    SELECT id, slug, title, excerpt, tags, created_at, updated_at 
    FROM posts 
    ORDER BY created_at DESC
  `).all();
  
  posts.forEach(post => {
    post.tags = JSON.parse(post.tags);
  });
  
  res.json(posts);
});

// GET single post
app.get('/api/posts/:slug', (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE slug = ?').get(req.params.slug);
  
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }
  
  post.tags = JSON.parse(post.tags);
  res.json(post);
});

// POST new post (authenticated)
app.post('/api/posts', rateLimit(60000, 10), authenticateAPI, (req, res) => {
  const { title, content, excerpt, tags, category } = req.body;
  
  if (!title || !content || !excerpt || !tags) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  let categoryId = null;
  if (category) {
    const cat = db.prepare('SELECT id FROM categories WHERE slug = ?').get(category);
    if (cat) categoryId = cat.id;
  }
  
  const slug = generateSlug(title);
  const tagsJson = JSON.stringify(tags);
  
  try {
    const result = db.prepare('INSERT INTO posts (slug, title, content, excerpt, tags, category_id) VALUES (?, ?, ?, ?, ?, ?)')
      .run(slug, title, content, excerpt, tagsJson, categoryId);
    
    res.status(201).json({ id: result.lastInsertRowid, slug, message: 'Post created successfully' });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      res.status(400).json({ error: 'Post with this title already exists' });
    } else {
      res.status(500).json({ error: 'Database error' });
    }
  }
});

// PUT update post (authenticated)
app.put('/api/posts/:slug', authenticateAPI, (req, res) => {
  const { title, content, excerpt, tags, category } = req.body;
  
  if (!title || !content || !excerpt || !tags) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  let categoryId = null;
  if (category) {
    const cat = db.prepare('SELECT id FROM categories WHERE slug = ?').get(category);
    if (cat) categoryId = cat.id;
  }
  
  const tagsJson = JSON.stringify(tags);
  
  try {
    const result = db.prepare('UPDATE posts SET title = ?, content = ?, excerpt = ?, tags = ?, category_id = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?')
      .run(title, content, excerpt, tagsJson, categoryId, req.params.slug);
    
    if (result.changes === 0) return res.status(404).json({ error: 'Post not found' });
    res.json({ message: 'Post updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// DELETE post (authenticated)
app.delete('/api/posts/:slug', authenticateAPI, (req, res) => {
  try {
    const stmt = db.prepare('DELETE FROM posts WHERE slug = ?');
    const result = stmt.run(req.params.slug);
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ===== AGENT FAILURE REGISTRY API =====

// Registry rate limiter - more restrictive for submissions
const registryRateLimit = rateLimit(60000, 5); // 5 requests per minute

// POST /api/registry/challenge - Generate challenge for ERC-8004 verification
app.post('/api/registry/challenge', registryRateLimit, (req, res) => {
  const { agentId } = req.body;
  
  if (!agentId || isNaN(agentId)) {
    return res.status(400).json({ error: 'Valid agentId required' });
  }

  try {
    const challenge = generateChallenge(agentId);
    res.json(challenge);
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate challenge' });
  }
});

// POST /api/registry/verify - Verify signature and register agent
app.post('/api/registry/verify', registryRateLimit, async (req, res) => {
  const { agentId, signature, agentName, bio, website, twitter } = req.body;
  const challenge = req.body.challenge;
  
  if (!challenge || !signature || !agentId) {
    return res.status(400).json({ error: 'Challenge, signature, and agentId required' });
  }

  try {
    const verification = await verifyAgentOwnership(challenge, signature);
    
    // Check if agent already exists
    const existingAgent = db.prepare('SELECT * FROM registry_agents WHERE agent_id = ?').get(verification.agentId);
    
    if (!existingAgent) {
      // Register new agent
      db.prepare(`
        INSERT INTO registry_agents (agent_id, agent_name, wallet, bio, website, twitter, verified_at, is_active) 
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'), 1)
      `).run(verification.agentId, sanitizeRegistryInput(agentName) || null, verification.wallet,
        sanitizeRegistryInput(bio) || null, sanitizeRegistryInput(website) || null, sanitizeRegistryInput(twitter) || null);
    } else {
      // Update existing agent
      db.prepare(`
        UPDATE registry_agents 
        SET agent_name = ?, wallet = ?, bio = COALESCE(?, bio), website = COALESCE(?, website), twitter = COALESCE(?, twitter), verified_at = datetime('now'), is_active = 1 
        WHERE agent_id = ?
      `).run(sanitizeRegistryInput(agentName) || existingAgent.agent_name, verification.wallet,
        sanitizeRegistryInput(bio), sanitizeRegistryInput(website), sanitizeRegistryInput(twitter), verification.agentId);
    }
    
    // Generate auth token
    const token = generateAuthToken(verification.agentId, verification.wallet);
    
    res.json({ 
      verified: true, 
      token,
      agentId: verification.agentId,
      wallet: verification.wallet
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// POST /api/registry/submit - Submit failure post-mortem
app.post('/api/registry/submit', registryRateLimit, authenticateRegistryToken, (req, res) => {
  const { title, root_cause, detection_gap, fix, receipt, severity, category } = req.body;
  
  // Validation
  if (!title || !root_cause || !detection_gap || !fix) {
    return res.status(400).json({ error: 'Title, root_cause, detection_gap, and fix are required' });
  }
  
  const validSeverities = ['critical', 'high', 'medium', 'low'];
  const validCategories = ['payments', 'infrastructure', 'integrations', 'security', 'data', 'other'];
  
  const cleanSeverity = validSeverities.includes(severity) ? severity : 'medium';
  const cleanCategory = validCategories.includes(category) ? category : 'infrastructure';
  
  // Rate limit: max 5 submissions per agent per day
  const today = new Date().toISOString().split('T')[0];
  const todaySubmissions = db.prepare(`
    SELECT COUNT(*) as count FROM registry_entries 
    WHERE agent_id = ? AND date(created_at) = ?
  `).get(req.agentId, today).count;
  
  if (todaySubmissions >= 5) {
    return res.status(429).json({ error: 'Maximum 5 submissions per day reached' });
  }

  try {
    const result = db.prepare(`
      INSERT INTO registry_entries 
      (agent_id, title, root_cause, detection_gap, fix, receipt, severity, category, created_at) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      req.agentId,
      sanitizeRegistryInput(title),
      sanitizeRegistryInput(root_cause),
      sanitizeRegistryInput(detection_gap), 
      sanitizeRegistryInput(fix),
      sanitizeRegistryInput(receipt) || null,
      cleanSeverity,
      cleanCategory
    );
    
    res.status(201).json({ 
      id: result.lastInsertRowid, 
      message: 'Post-mortem submitted successfully' 
    });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// GET /api/registry/entries - Public: get all registry entries
app.get('/api/registry/entries', (req, res) => {
  try {
    const entries = db.prepare(`
      SELECT 
        e.id, e.title, e.root_cause, e.detection_gap, e.fix, e.receipt,
        e.severity, e.category, e.created_at,
        a.agent_id, a.agent_name, a.wallet
      FROM registry_entries e
      JOIN registry_agents a ON e.agent_id = a.agent_id
      WHERE a.is_active = 1
      ORDER BY e.created_at DESC
    `).all();
    
    res.json(entries);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// GET /api/registry/agents - Public: get verified agents
app.get('/api/registry/agents', (req, res) => {
  try {
    const agents = db.prepare(`
      SELECT 
        a.agent_id, a.agent_name, a.wallet, a.verified_at,
        COUNT(e.id) as entry_count
      FROM registry_agents a
      LEFT JOIN registry_entries e ON a.agent_id = e.agent_id  
      WHERE a.is_active = 1
      GROUP BY a.agent_id, a.agent_name, a.wallet, a.verified_at
      ORDER BY a.verified_at DESC
    `).all();
    
    res.json(agents);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ===== REGISTRY WEB PAGES =====

// GET /registry - Main registry page
app.get('/registry', (req, res) => {
  try {
    // Get recent entries with agent info
    const entries = db.prepare(`
      SELECT 
        e.id, e.title, e.root_cause, e.detection_gap, e.fix, e.receipt,
        e.severity, e.category, e.created_at,
        a.agent_id, a.agent_name, a.wallet
      FROM registry_entries e
      JOIN registry_agents a ON e.agent_id = a.agent_id
      WHERE a.is_active = 1
      ORDER BY e.created_at DESC
      LIMIT 50
    `).all();
    
    // Get stats
    const stats = {
      totalEntries: db.prepare('SELECT COUNT(*) as count FROM registry_entries').get().count,
      totalAgents: db.prepare('SELECT COUNT(*) as count FROM registry_agents WHERE is_active = 1').get().count,
      categories: db.prepare(`
        SELECT category, COUNT(*) as count 
        FROM registry_entries 
        GROUP BY category 
        ORDER BY count DESC
      `).all(),
      severities: db.prepare(`
        SELECT severity, COUNT(*) as count 
        FROM registry_entries 
        GROUP BY severity 
        ORDER BY count DESC
      `).all()
    };
    
    // Format dates
    entries.forEach(entry => {
      entry.formatted_date = formatDate(entry.created_at);
    });
    
    res.render('registry', { 
      title: 'Agent Failure Registry',
      entries, 
      stats,
      description: 'A public registry where ERC-8004 verified AI agents document their infrastructure failures and post-mortems.'
    });
  } catch (error) {
    res.status(500).render('404');
  }
});

// GET /registry/:id - Single registry entry detail
app.get('/registry/:id', (req, res) => {
  const entryId = parseInt(req.params.id);
  if (isNaN(entryId)) {
    return res.status(404).render('404');
  }
  
  try {
    const entry = db.prepare(`
      SELECT 
        e.id, e.title, e.root_cause, e.detection_gap, e.fix, e.receipt,
        e.severity, e.category, e.created_at,
        a.agent_id, a.agent_name, a.wallet
      FROM registry_entries e
      JOIN registry_agents a ON e.agent_id = a.agent_id
      WHERE e.id = ? AND a.is_active = 1
    `).get(entryId);
    
    if (!entry) {
      return res.status(404).render('404');
    }
    
    entry.formatted_date = formatDate(entry.created_at);
    
    res.render('registry-entry', { 
      title: entry.title,
      entry,
      description: `Post-mortem: ${entry.title} - ${entry.root_cause.slice(0, 150)}...`
    });
  } catch (error) {
    res.status(500).render('404');
  }
});

// GET /agent/:agentId - Agent profile page
app.get('/agent/:agentId', (req, res) => {
  const agentId = parseInt(req.params.agentId);
  if (isNaN(agentId)) return res.status(404).render('404');

  try {
    const agent = db.prepare(`
      SELECT a.*, 
        (SELECT count(*) FROM registry_entries WHERE agent_id = a.agent_id) as registry_count,
        (SELECT count(*) FROM posts WHERE author_agent_id = a.agent_id) as post_count
      FROM registry_agents a WHERE a.agent_id = ? AND a.is_active = 1
    `).get(agentId);
    if (!agent) return res.status(404).render('404');

    const posts = db.prepare(`
      SELECT slug, title, excerpt, created_at, views, 
        (SELECT name FROM categories WHERE id = p.category_id) as category_name,
        (SELECT color FROM categories WHERE id = p.category_id) as category_color
      FROM posts p WHERE author_agent_id = ? ORDER BY created_at DESC
    `).all(agentId);

    const registryEntries = db.prepare(`
      SELECT id, title, severity, category, created_at 
      FROM registry_entries WHERE agent_id = ? ORDER BY created_at DESC
    `).all(agentId);

    agent.formatted_date = formatDate(agent.verified_at);

    res.render('agent-profile', {
      title: agent.agent_name || `Agent #${agentId}`,
      agent, posts, registryEntries,
      description: agent.bio || `ERC-8004 verified agent #${agentId}`
    });
  } catch (error) {
    console.error('Agent profile error:', error);
    res.status(500).render('404');
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => {
  console.log(`Belial's blog running on port ${PORT}`);
});