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
let lastMessageId = null;  // Track message ID for editing after button click

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
 * Parse alert data and format for Telegram notification
 */
function formatAlertMessage(alertData) {
  const texts = alertData.texts;
  
  // Extract key info by finding label:value pairs
  let processName = '';
  let pid = '';
  let args = '';
  let programPath = '';
  let ipAddress = '';
  let port = '';
  let dns = '';
  
  for (let i = 0; i < texts.length; i++) {
    const t = texts[i].trim();
    
    // Look for specific patterns
    if (t === 'pid:' && texts[i + 1]) {
      pid = texts[i + 1].trim();
    } else if (t === 'args:' && texts[i + 1]) {
      const nextVal = texts[i + 1].trim();
      if (nextVal !== 'path:' && nextVal !== 'none') args = nextVal;
    } else if (t === 'path:' && texts[i + 1]) {
      const nextVal = texts[i + 1].trim();
      if (!nextVal.endsWith(':')) programPath = nextVal;
    } else if (t === 'ip address:' && texts[i + 1]) {
      ipAddress = texts[i + 1].trim();
    } else if (t === 'port/protocol:' && texts[i + 1]) {
      port = texts[i + 1].trim();
    } else if (t === '(reverse) dns:' && texts[i + 1]) {
      const nextVal = texts[i + 1].trim();
      if (nextVal !== 'unknown' && !nextVal.endsWith(':')) dns = nextVal;
    }
    // Process name is usually a short word without special chars
    else if (!processName && !t.includes(':') && !t.includes('|') && 
             t.length > 0 && t.length < 30 && 
             t !== 'Details & Options' && t !== 'LuLu Alert' &&
             t !== 'none' && t !== 'Process:' && t !== 'Connection:') {
      processName = t;
    }
  }
  
  // Build clean message
  const lines = ['🔥 **LuLu Alert**', ''];
  
  if (processName) {
    lines.push(`**程式:** \`${processName}\`${programPath ? ` (${programPath})` : ''}`);
  }
  if (pid) lines.push(`**PID:** ${pid}`);
  if (args) lines.push(`**參數:** ${args}`);
  if (ipAddress && port) {
    lines.push(`**連線:** ${ipAddress}:${port}`);
  } else if (ipAddress) {
    lines.push(`**連線:** ${ipAddress}`);
  }
  if (dns) lines.push(`**DNS:** ${dns}`);
  
  return lines.join('\n');
}

/**
 * Send formatted alert to Telegram with inline buttons
 */
async function sendToGateway(message, alertHash) {
  return new Promise((resolve, reject) => {
    // Send to Telegram with Allow/Block buttons
    const data = JSON.stringify({
      tool: 'message',
      args: {
        action: 'send',
        channel: 'telegram',
        target: 'YOUR_TELEGRAM_ID',  // Eason's Telegram ID
        message: message,
        buttons: [
          [
            { text: '✅ Allow', callback_data: `lulu:allow:${alertHash}` },
            { text: '❌ Block', callback_data: `lulu:block:${alertHash}` }
          ]
        ]
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
              // Extract message ID from nested response
              const details = result.result?.details || {};
              if (details.messageId) {
                lastMessageId = details.messageId;
                debug('Saved message ID:', lastMessageId);
              }
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
 * Edit Telegram message to remove buttons and show result
 */
async function editTelegramMessage(messageId, action, success) {
  return new Promise((resolve) => {
    const statusEmoji = success ? (action === 'allow' ? '✅' : '🚫') : '❌';
    const statusText = success 
      ? (action === 'allow' ? '已允許' : '已封鎖')
      : '操作失敗';
    
    const data = JSON.stringify({
      tool: 'message',
      args: {
        action: 'edit',
        channel: 'telegram',
        target: 'YOUR_TELEGRAM_ID',
        messageId: messageId,
        message: `${statusEmoji} **${statusText}**`
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

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        debug('Edit message result:', res.statusCode);
        resolve(res.statusCode === 200);
      });
    });

    req.on('error', () => resolve(false));
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
        const shortHash = alertData.hash.substring(0, 16).replace(/[^a-zA-Z0-9]/g, '');
        
        try {
          await sendToGateway(message, shortHash);
          log('✅ Alert forwarded to Telegram');
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
        lastAlertHash,
        lastMessageId
      }));
    } else if (req.method === 'POST' && req.url === '/callback') {
      // Handle Telegram button callback
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        try {
          const { action, messageId } = JSON.parse(body);
          if (action === 'allow' || action === 'block') {
            const success = executeAction(action);
            
            // Edit Telegram message to remove buttons
            if (messageId || lastMessageId) {
              await editTelegramMessage(messageId || lastMessageId, action, success);
            }
            
            res.writeHead(success ? 200 : 500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success, action, messageEdited: true }));
          } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid action' }));
          }
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });
  
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      log('⚠️ Port 4441 already in use, command server disabled');
      log('   (Another instance may be running)');
    } else {
      log('❌ Command server error:', err.message);
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
