/**
 * LuLu Monitor - Main Entry
 * Monitors LuLu Firewall alerts and forwards to OpenClaw Gateway
 */

const { execSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const SCRIPTS_DIR = path.join(__dirname, '..', 'scripts');

const CONFIG = {
  pollInterval: 1000,      // Check every 1 second
  gatewayPort: 18789,      // Default, will be loaded from config
  gatewayHost: '127.0.0.1',
  verbose: process.argv.includes('--verbose') || process.argv.includes('-v')
};

let lastAlertHash = null;
let gatewayToken = null;

function log(...args) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}]`, ...args);
}

function debug(...args) {
  if (CONFIG.verbose) {
    log('[DEBUG]', ...args);
  }
}

/**
 * Load Gateway config (token and port) from OpenClaw config
 */
function loadGatewayConfig() {
  const possiblePaths = [
    path.join(process.env.HOME, '.openclaw', 'openclaw.json'),
    path.join(process.env.HOME, '.openclaw', 'clawdbot.json'),
    path.join(process.env.HOME, '.clawdbot', 'clawdbot.json')
  ];
  
  for (const configPath of possiblePaths) {
    try {
      const configData = fs.readFileSync(configPath, 'utf8');
      const config = JSON.parse(configData);
      
      // Get port
      if (config.port) {
        CONFIG.gatewayPort = config.port;
        debug('Loaded gateway port:', CONFIG.gatewayPort);
      }
      
      // Get token (nested under gateway.auth.token)
      if (config.gateway?.auth?.token) {
        gatewayToken = config.gateway.auth.token;
        debug('Loaded gateway token from', configPath);
      }
      
      return true;
    } catch (e) {
      // Try next path
    }
  }
  debug('Could not load gateway config from any file');
  return false;
}

/**
 * Run AppleScript file
 */
function runScript(scriptName) {
  const scriptPath = path.join(SCRIPTS_DIR, scriptName);
  try {
    const result = execSync(`osascript "${scriptPath}"`, {
      encoding: 'utf8',
      timeout: 10000
    }).trim();
    return result;
  } catch (e) {
    debug(`Script ${scriptName} error:`, e.message);
    return null;
  }
}

/**
 * Check if LuLu alert window exists
 */
function checkForAlert() {
  const result = runScript('check-alert.scpt');
  return result === 'true';
}

/**
 * Extract all text from LuLu alert window
 */
function extractAlertData() {
  const result = runScript('extract-alert.scpt');
  if (!result) return null;
  
  const texts = result.split('|||').filter(t => t.trim());
  return {
    texts,
    hash: texts.join('|').substring(0, 200),
    timestamp: Date.now()
  };
}

/**
 * Format alert for OpenClaw
 */
function formatAlertMessage(alertData) {
  return [
    '🔥 **LuLu Firewall Alert** - Action Required',
    '',
    'A process is trying to make a network connection. Please analyze and decide.',
    '',
    '**Extracted text from alert:**',
    '```',
    ...alertData.texts,
    '```',
    '',
    'Based on this information:',
    '1. Identify the process and what it\'s connecting to',
    '2. Assess if this is expected/safe',
    '3. Run: `~/clawd/lulu-monitor/scripts/lulu-action.sh allow` or `block`',
    '',
    `_Alert hash: ${alertData.hash.substring(0, 16)}_`
  ].join('\n');
}

/**
 * Send wake event to OpenClaw Gateway via /tools/invoke
 */
async function sendToGateway(message) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({
      tool: 'cron',
      args: {
        action: 'wake',
        text: message,
        mode: 'now'
      }
    });

    const options = {
      hostname: CONFIG.gatewayHost,
      port: CONFIG.gatewayPort,
      path: '/tools/invoke',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...(gatewayToken && { 'Authorization': `Bearer ${gatewayToken}` })
      },
      timeout: 10000
    };

    debug('Sending to gateway:', options.hostname + ':' + options.port + options.path);

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode === 200) {
          try {
            const result = JSON.parse(body);
            if (result.ok) {
              debug('Sent to Gateway successfully');
              resolve(true);
            } else {
              debug('Gateway returned error:', result);
              reject(new Error(result.error?.message || 'Unknown error'));
            }
          } catch (e) {
            debug('Failed to parse response:', body);
            resolve(true); // Assume success if we got 200
          }
        } else {
          debug('Gateway response:', res.statusCode, body);
          reject(new Error(`Gateway returned ${res.statusCode}`));
        }
      });
    });

    req.on('error', (e) => {
      debug('Gateway request error:', e.message);
      reject(e);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    req.write(data);
    req.end();
  });
}

/**
 * Main poll function
 */
async function poll() {
  try {
    const hasAlert = checkForAlert();
    
    if (hasAlert) {
      const alertData = extractAlertData();
      
      if (alertData && alertData.hash !== lastAlertHash) {
        log('🚨 New LuLu alert detected!');
        log('   Texts:', alertData.texts.slice(0, 3).join(', ') + '...');
        lastAlertHash = alertData.hash;
        
        const message = formatAlertMessage(alertData);
        
        try {
          await sendToGateway(message);
          log('✅ Alert forwarded to OpenClaw');
        } catch (e) {
          log('⚠️ Failed to send to Gateway:', e.message);
          // Write to file as fallback
          const fallbackPath = path.join(process.env.HOME, '.openclaw', 'lulu-alert.txt');
          try {
            fs.mkdirSync(path.dirname(fallbackPath), { recursive: true });
            fs.writeFileSync(fallbackPath, message);
            log('📝 Wrote alert to fallback file:', fallbackPath);
          } catch (writeErr) {
            log('❌ Failed to write fallback:', writeErr.message);
          }
        }
      }
    } else if (lastAlertHash) {
      debug('Alert dismissed');
      lastAlertHash = null;
    }
  } catch (e) {
    debug('Poll error:', e.message);
  }
  
  setTimeout(poll, CONFIG.pollInterval);
}

/**
 * Create simple HTTP server for receiving commands
 */
function startCommandServer() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/action') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const { action } = JSON.parse(body);
          if (action === 'allow' || action === 'block') {
            const success = executeAction(action);
            res.writeHead(success ? 200 : 500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success, action }));
          } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid action. Use "allow" or "block"' }));
          }
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
    } else if (req.method === 'GET' && req.url === '/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        running: true, 
        hasAlert: checkForAlert(),
        lastAlertHash 
      }));
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });
  
  server.listen(4441, '127.0.0.1', () => {
    log('📡 Command server listening on http://127.0.0.1:4441');
  });
}

/**
 * Execute action on LuLu alert
 */
function executeAction(action) {
  log(`Executing: ${action}`);
  
  const scriptName = action === 'allow' ? 'click-allow.scpt' : 'click-block.scpt';
  const result = runScript(scriptName);
  
  if (result !== null) {
    log(`✅ Clicked ${action}`);
    lastAlertHash = null; // Reset after action
    return true;
  } else {
    log(`❌ Failed to click ${action}`);
    return false;
  }
}

// CLI action handler - allow running as: node index.js allow|block
const action = process.argv[2];
if (action === 'allow' || action === 'block') {
  const success = executeAction(action);
  process.exit(success ? 0 : 1);
}

// Main
log('🔍 LuLu Monitor starting...');
loadGatewayConfig();
startCommandServer();
poll();
log('👀 Watching for LuLu alerts...');
