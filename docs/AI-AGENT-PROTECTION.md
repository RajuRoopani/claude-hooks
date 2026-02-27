# AI Agent & Bot Protection — Production Safeguards

This document defines the mandatory security controls required to protect this service from being accessed or scraped by AI agents (Claude, OpenAI, DeepSeek, Ollama, etc.), automated crawlers, and headless HTTP clients.

All layers below are **required**. They must be implemented, reviewed, and verified before any production deployment.

---

## Checklist

- [ ] `robots.txt` and `llms.txt` served at root
- [ ] User-agent blocklist configured at server/CDN level
- [ ] Known AI provider IP ranges blocked at WAF/firewall
- [ ] Rate limiting enforced on all routes
- [ ] JavaScript challenge enabled on non-API routes (Cloudflare Turnstile or equivalent)
- [ ] All sensitive/API endpoints require authentication
- [ ] HTTP header fingerprinting middleware active
- [ ] Behavioral anomaly logging enabled
- [ ] Bot protection reviewed and tested before each production release

---

## Layer 1: Protocol-Level Hints

### `public/robots.txt`

Place at the root of your domain (`https://yourdomain.com/robots.txt`):

```
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: anthropic-ai
Disallow: /

User-agent: Google-Extended
Disallow: /

User-agent: PerplexityBot
Disallow: /

User-agent: Bytespider
Disallow: /

User-agent: OAI-SearchBot
Disallow: /

User-agent: Meta-ExternalAgent
Disallow: /

User-agent: Amazonbot
Disallow: /

User-agent: DuckAssistBot
Disallow: /

User-agent: cohere-ai
Disallow: /

User-agent: YouBot
Disallow: /

User-agent: PetalBot
Disallow: /
```

### `public/llms.txt`

Emerging standard for LLM access control. Place at `https://yourdomain.com/llms.txt`:

```
# This service does not permit access by AI/LLM agents.
User-agent: *
Disallow: /
```

---

## Layer 2: User-Agent Blocklist

### Nginx

Add to your `nginx.conf` or server block:

```nginx
map $http_user_agent $block_ai_agent {
    default             0;
    ~*GPTBot            1;
    ~*ClaudeBot         1;
    ~*anthropic         1;
    ~*openai            1;
    ~*Bytespider        1;
    ~*PetalBot          1;
    ~*Amazonbot         1;
    ~*PerplexityBot     1;
    ~*YouBot            1;
    ~*cohere-ai         1;
    ~*Meta-ExternalAgent 1;
    ~*DuckAssistBot     1;
    ~*OAI-SearchBot     1;
    ~*Google-Extended   1;
}

server {
    if ($block_ai_agent) {
        return 403 '{"error":"Forbidden"}';
    }
}
```

### Express.js / Node.js Middleware

```js
// middleware/blockAiAgents.js
const BLOCKED_UA_PATTERNS = [
  /GPTBot/i,
  /ClaudeBot/i,
  /anthropic/i,
  /Bytespider/i,
  /PetalBot/i,
  /Amazonbot/i,
  /PerplexityBot/i,
  /cohere-ai/i,
  /DuckAssistBot/i,
  /OAI-SearchBot/i,
  /Meta-ExternalAgent/i,
  /Google-Extended/i,
  /YouBot/i,
];

module.exports = function blockAiAgents(req, res, next) {
  const ua = req.headers['user-agent'] || '';
  if (BLOCKED_UA_PATTERNS.some((pattern) => pattern.test(ua))) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};
```

```js
// app.js
const blockAiAgents = require('./middleware/blockAiAgents');
app.use(blockAiAgents);
```

### Python / FastAPI

```python
# middleware/block_ai_agents.py
import re
from fastapi import Request
from fastapi.responses import JSONResponse

BLOCKED_UA_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"GPTBot", r"ClaudeBot", r"anthropic", r"Bytespider",
        r"PetalBot", r"Amazonbot", r"PerplexityBot", r"cohere-ai",
        r"DuckAssistBot", r"OAI-SearchBot", r"Meta-ExternalAgent",
        r"Google-Extended", r"YouBot",
    ]
]

async def block_ai_agents_middleware(request: Request, call_next):
    ua = request.headers.get("user-agent", "")
    if any(p.search(ua) for p in BLOCKED_UA_PATTERNS):
        return JSONResponse(status_code=403, content={"error": "Forbidden"})
    return await call_next(request)
```

```python
# main.py
from fastapi.middleware.base import BaseHTTPMiddleware
app.add_middleware(BaseHTTPMiddleware, dispatch=block_ai_agents_middleware)
```

> **Note:** User-agent spoofing is trivial. This layer stops polite/compliant crawlers only. It must be combined with deeper layers below.

---

## Layer 3: IP Blocklisting

Block known AI provider IP ranges at the firewall or WAF before requests reach your application.

### Cloudflare WAF Rule (recommended)

Create a WAF custom rule:

```
Expression:
  (ip.geoip.asnum in {396982 16509 14618 8075 8987}) and not cf.verified_bot

Action: Block
```

ASNs covered:
- `396982` — Google Cloud (Vertex AI, Gemini)
- `16509` — Amazon AWS (Bedrock, SageMaker)
- `14618` — Amazon AWS (additional range)
- `8075`  — Microsoft Azure (OpenAI Service)
- `8987`  — Various AI hosting providers

### Linux iptables + ipset

```bash
# Create a persistent blocklist
ipset create ai_providers hash:net

# OpenAI published ranges (check https://openai.com/gptbot-ranges.txt for updates)
ipset add ai_providers 23.102.140.112/28
ipset add ai_providers 13.65.240.240/28
ipset add ai_providers 40.84.180.224/28

# Apply at firewall level
iptables -I INPUT  -m set --match-set ai_providers src -j DROP
iptables -I FORWARD -m set --match-set ai_providers src -j DROP

# Persist across reboots
service ipset save
iptables-save > /etc/iptables/rules.v4
```

**Maintenance:** AI provider IP ranges change. Subscribe to provider security feeds or schedule a weekly review of published ranges.

---

## Layer 4: Rate Limiting

### Nginx

```nginx
# Define zones in http block
http {
    limit_req_zone $binary_remote_addr zone=general:10m rate=30r/m;
    limit_req_zone $binary_remote_addr zone=api:10m     rate=10r/m;
    limit_req_zone $binary_remote_addr zone=auth:10m    rate=5r/m;

    server {
        # General pages
        location / {
            limit_req zone=general burst=10 nodelay;
            limit_req_status 429;
        }

        # API endpoints — stricter
        location /api/ {
            limit_req zone=api burst=3 nodelay;
            limit_req_status 429;
        }

        # Auth endpoints — strictest
        location /auth/ {
            limit_req zone=auth burst=2 nodelay;
            limit_req_status 429;
        }
    }
}
```

### Express.js (using `express-rate-limit` + Redis)

```bash
npm install express-rate-limit rate-limit-redis ioredis
```

```js
// middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const Redis = require('ioredis');

const redis = new Redis(process.env.REDIS_URL);

const createLimiter = (windowMs, max, message) =>
  rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message },
    store: new RedisStore({ sendCommand: (...args) => redis.call(...args) }),
  });

module.exports = {
  generalLimiter: createLimiter(60_000, 30, 'Too many requests'),
  apiLimiter:     createLimiter(60_000, 10, 'API rate limit exceeded'),
  authLimiter:    createLimiter(60_000,  5, 'Too many auth attempts'),
};
```

```js
// app.js
const { generalLimiter, apiLimiter, authLimiter } = require('./middleware/rateLimiter');
app.use('/',      generalLimiter);
app.use('/api/',  apiLimiter);
app.use('/auth/', authLimiter);
```

---

## Layer 5: JavaScript Challenge

JavaScript challenges block raw HTTP clients — the most common agent access pattern. Agents making direct HTTP calls cannot execute JavaScript and will fail the challenge silently.

### Cloudflare Turnstile (Recommended — Free, No CAPTCHA UX)

1. Log in to Cloudflare Dashboard → **Turnstile** → Create a widget
2. Add to your HTML:

```html
<head>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>

<form>
  <div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
  <button type="submit">Submit</button>
</form>
```

3. Verify the token server-side on form/API submission:

```js
// server-side token verification
async function verifyTurnstile(token, remoteIp) {
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: process.env.TURNSTILE_SECRET_KEY,
      response: token,
      remoteip: remoteIp,
    }),
  });
  const data = await response.json();
  return data.success === true;
}
```

### Cloudflare WAF — Managed Challenge for All Non-API Routes

In Cloudflare WAF, create a rule:

```
Expression:
  (not http.request.uri.path matches "^/api/") and
  (not cf.verified_bot)

Action: Managed Challenge
```

---

## Layer 6: Authentication on All Sensitive Endpoints

All API and sensitive endpoints must require authentication. Unauthenticated access must be denied at the middleware level.

```js
// middleware/requireAuth.js
const jwt = require('jsonwebtoken');

module.exports = function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    req.user = jwt.verify(authHeader.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};
```

```js
// Apply to all API routes
app.use('/api/', requireAuth);
```

**Requirements:**
- JWTs must use short expiry (15 minutes for access tokens, 7 days for refresh tokens)
- Rotate JWT secrets on a schedule and on any suspected compromise
- For B2B or internal services, prefer mutual TLS (mTLS) over bearer tokens

---

## Layer 7: HTTP Header Fingerprinting

Legitimate browser requests always include a consistent set of headers. Raw HTTP clients (agents, curl, scripts) often omit them.

```js
// middleware/headerFingerprint.js
const REQUIRED_HEADERS = ['accept', 'accept-encoding', 'accept-language'];

module.exports = function headerFingerprint(req, res, next) {
  // Skip for API endpoints (API clients legitimately omit browser headers)
  if (req.path.startsWith('/api/')) return next();

  const missing = REQUIRED_HEADERS.filter((h) => !req.headers[h]);
  if (missing.length > 0) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};
```

```python
# FastAPI equivalent
REQUIRED_HEADERS = {"accept", "accept-encoding", "accept-language"}

async def header_fingerprint_middleware(request: Request, call_next):
    if not request.url.path.startswith("/api/"):
        present = set(request.headers.keys())
        if not REQUIRED_HEADERS.issubset(present):
            return JSONResponse(status_code=403, content={"error": "Forbidden"})
    return await call_next(request)
```

---

## Layer 8: Logging & Anomaly Detection

All blocked requests must be logged with enough context to tune rules and detect patterns.

```js
// middleware/botLogger.js
const logger = require('../lib/logger'); // your structured logger (e.g., winston, pino)

module.exports = function botLogger(req, res, next) {
  res.on('finish', () => {
    if ([403, 429].includes(res.statusCode)) {
      logger.warn('blocked_request', {
        status:     res.statusCode,
        ip:         req.ip,
        ua:         req.headers['user-agent'],
        path:       req.path,
        method:     req.method,
        timestamp:  new Date().toISOString(),
        referer:    req.headers['referer'] || null,
        cf_score:   req.headers['cf-bot-management-score'] || null,
      });
    }
  });
  next();
};
```

**Alert thresholds to monitor:**
- More than 50 `403` responses from a single IP in 5 minutes → auto-block
- More than 100 `429` responses from a single IP in 1 minute → escalate
- Any request with a known AI user-agent that bypasses user-agent filter → investigate

---

## Cloudflare — Recommended Production Configuration Summary

If using Cloudflare (strongly recommended), enable the following:

| Setting | Value |
|---------|-------|
| Bot Fight Mode | **On** (Pro plan) or Super Bot Fight Mode (Business) |
| Security Level | **Medium** or **High** |
| Browser Integrity Check | **On** |
| Challenge TTL | **30 minutes** |
| WAF Rule — AI ASNs | **Block** (see Layer 3) |
| WAF Rule — Non-API JS Challenge | **Managed Challenge** (see Layer 5) |
| Rate Limiting | **On** per endpoint group |
| Turnstile | **Enabled** on all forms and sensitive endpoints |

---

## Maintenance & Review Requirements

| Task | Frequency |
|------|-----------|
| Review and update AI crawler user-agent list | Monthly |
| Sync blocked IP ranges with provider published lists | Monthly |
| Review blocked request logs for new patterns | Weekly |
| Rotate JWT secrets and API keys | Quarterly |
| Run bot simulation test against staging environment | Before each production release |
| Audit Cloudflare WAF rules for coverage gaps | Quarterly |

---

## Testing

Before each production deployment, verify protection is active:

```bash
# Should return 403
curl -A "GPTBot/1.0" https://yourdomain.com/

# Should return 403 (missing browser headers)
curl https://yourdomain.com/

# Should return 429 after burst
for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code}\n" https://yourdomain.com/api/endpoint; done

# Should return 401
curl https://yourdomain.com/api/protected

# Legitimate browser-like request — should return 200
curl \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "Accept: text/html,application/xhtml+xml" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  https://yourdomain.com/
```

---

## Defense-in-Depth Summary

| Layer | Method | Stops |
|-------|--------|-------|
| 1 | `robots.txt` / `llms.txt` | Polite, compliant crawlers |
| 2 | User-agent blocklist | Named AI crawlers |
| 3 | IP blocklisting (WAF/iptables) | IP-identifiable AI infrastructure |
| 4 | Rate limiting | Automated flooding and scraping |
| 5 | JavaScript challenge (Turnstile) | Raw HTTP clients and headless agents |
| 6 | Authentication (JWT / mTLS) | All unauthenticated access |
| 7 | Header fingerprinting | Minimal HTTP clients |
| 8 | Logging & anomaly detection | Novel and evolving attack patterns |

No single layer is sufficient. All eight layers must be active in production.
