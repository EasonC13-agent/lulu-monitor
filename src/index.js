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
  verbose: process.argv.includes('--verbose') || process.argv.includes('-v'),
  autoExecute: false,      // Auto-execute on high confidence (requires user opt-in)
  autoExecuteAction: 'allow-once',  // 'allow-once' (conservative) or 'allow' (permanent)
  telegramIds: [],  // Required: set in config.json or LULU_TELEGRAM_ID env
  telegramNames: {} // Optional: map of telegramId -> display name
};

let lastAlertHash = null;
let gatewayToken = null;
let lastMessageIds = {};  // Track message IDs per telegramId for editing after button click
let lastMessageContent = null;  // Track original message content for editing
const LOGS_DIR = path.join(__dirname, '..', 'logs');

/**
 * Append to action log file
 */
function logAction(alertInfo, action, userId, success) {
  try {
    fs.mkdirSync(LOGS_DIR, { recursive: true });
    const logFile = path.join(LOGS_DIR, 'actions.jsonl');
    const entry = {
      timestamp: new Date().toISOString(),
      alert: alertInfo || lastMessageContent?.substring(0, 200),
      action,
      userId,
      userName: CONFIG.telegramNames[userId] || userId,
      success,
      messageIds: { ...lastMessageIds }
    };
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  } catch (e) {
    debug('Failed to write action log:', e.message);
  }
}

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
 * Load local LuLu Monitor config
 */
function loadLocalConfig() {
  const configPath = path.join(__dirname, '..', 'config.json');
  try {
    const configData = fs.readFileSync(configPath, 'utf8');
    const config = JSON.parse(configData);
    
    if (typeof config.autoExecute === 'boolean') {
      CONFIG.autoExecute = config.autoExecute;
      debug('Auto-execute mode:', CONFIG.autoExecute ? 'ENABLED' : 'disabled');
    }
    if (config.autoExecuteAction === 'allow' || config.autoExecuteAction === 'allow-once') {
      CONFIG.autoExecuteAction = config.autoExecuteAction;
      debug('Auto-execute action:', CONFIG.autoExecuteAction);
    }
    // Support both telegramId (string) and telegramIds (array)
    if (config.telegramIds && Array.isArray(config.telegramIds)) {
      CONFIG.telegramIds = config.telegramIds;
    } else if (config.telegramId) {
      CONFIG.telegramIds = [config.telegramId];
    }
    if (config.telegramNames) {
      CONFIG.telegramNames = config.telegramNames;
    }
    debug('Telegram IDs:', CONFIG.telegramIds);
  } catch (e) {
    debug('No local config found, using defaults');
  }
  
  // Env var override (comma-separated)
  if (process.env.LULU_TELEGRAM_ID) {
    CONFIG.telegramIds = process.env.LULU_TELEGRAM_ID.split(',').map(s => s.trim());
    debug('Telegram IDs from env:', CONFIG.telegramIds);
  }
  
  if (!CONFIG.telegramIds.length) {
    log('ERROR: telegramIds is required. Set telegramId/telegramIds in config.json or LULU_TELEGRAM_ID env var.');
    process.exit(1);
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
 * Format alert data for OpenClaw analysis
 * Uses pattern matching since UI text order is unpredictable
 */
function formatAlertMessage(alertData) {
  const texts = alertData.texts;
  const allText = texts.join(' ');
  
  // Pattern matching for values
  let processName = '';
  let pid = '';
  let args = '';
  let programPath = '';
  let ipAddress = '';
  let port = '';
  let dns = '';
  
  // Skip labels and UI elements
  const skipPatterns = [
    'Details & Options', 'LuLu Alert', 'Process:', 'Connection:',
    'pid:', 'args:', 'path:', 'port/protocol:', 'ip address:',
    '(reverse) dns:', 'Rule Scope:', 'Rule Duration:', 'Time stamp:',
    'none', 'unknown'
  ];
  
  for (const t of texts) {
    const trimmed = t.trim();
    if (!trimmed) continue;
    
    // Skip labels and UI elements
    if (skipPatterns.some(p => trimmed.toLowerCase() === p.toLowerCase())) continue;
    if (trimmed.endsWith(':')) continue;
    
    // IP address pattern (IPv4)
    if (!ipAddress && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
      ipAddress = trimmed;
      continue;
    }
    
    // Port pattern: "443 (TCP)" or "53 (UDP)"
    if (!port && /^\d+\s*\((TCP|UDP)\)$/i.test(trimmed)) {
      port = trimmed;
      continue;
    }
    
    // PID: pure number, 4-6 digits
    if (!pid && /^\d{4,6}$/.test(trimmed)) {
      pid = trimmed;
      continue;
    }
    
    // Path: starts with /
    if (!programPath && trimmed.startsWith('/')) {
      programPath = trimmed;
      continue;
    }
    
    // Args: starts with - or contains URL/path-like content
    if (!args && (trimmed.startsWith('-') || trimmed.includes('://'))) {
      args = trimmed;
      continue;
    }
    
    // DNS: contains dots but not IP
    if (!dns && trimmed.includes('.') && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
      dns = trimmed;
      continue;
    }
    
    // Process name: short string without special chars, first one found
    if (!processName && trimmed.length > 0 && trimmed.length < 30 && 
        /^[a-zA-Z0-9_-]+$/.test(trimmed)) {
      processName = trimmed;
      continue;
    }
  }
  
  // Build message for OpenClaw to analyze
  const lines = [
    '[LULU_ALERT]',
    `process: ${processName || 'unknown'}`,
    `pid: ${pid || 'unknown'}`,
    `path: ${programPath || 'unknown'}`,
    `args: ${args || 'none'}`,
    `ip: ${ipAddress || 'unknown'}`,
    `port: ${port || 'unknown'}`,
    `dns: ${dns || 'unknown'}`,
    '[/LULU_ALERT]',
    '',
    '請分析這個 LuLu 防火牆警報：',
    '1. 識別程式和連線目標',
    '2. 評估風險等級 (🟢低/🟡中/🔴高)',
    '3. 給出建議 (Allow/Block, 永久或本次)',
  ];
  
  // Add auto-execute instructions if enabled
  if (CONFIG.autoExecute) {
    lines.push('');
    lines.push('⚡ 自動執行模式已開啟：');
    lines.push('如果你對決策有高度信心（已知安全程式如 curl/brew/node/git/系統服務連到正常目標），');
    lines.push('可以直接執行動作：');
    lines.push('1. 先調用 exec: curl -X POST http://127.0.0.1:4441/callback -H "Content-Type: application/json" -d "{\\"action\\":\\"' + CONFIG.autoExecuteAction + '\\"}"');
    lines.push('2. 然後發送 Telegram 通知（無按鈕），說明已自動允許及原因');
    lines.push('');
    lines.push('如果信心不足或有任何疑慮，改為發送帶按鈕的通知讓用戶決定。');
  }
  
  lines.push('');
  lines.push('⚠️ 重要：不要自己發送 Telegram 訊息！只需要把分析結果寫入檔案，monitor 會自動發送給所有用戶。');
  lines.push('');
  lines.push('請把你的分析摘要（包含程式名、目標、風險等級、建議）寫入以下檔案：');
  lines.push('exec command: cat > /tmp/lulu-analysis.txt << \'ANALYSIS_EOF\'');
  lines.push('<你的完整分析摘要>');
  lines.push('ANALYSIS_EOF');
  lines.push('');
  lines.push('格式範例：');
  lines.push('[LuLu] 🟢 低風險');
  lines.push('');
  lines.push('程式: curl');
  lines.push('目標: example.com (1.2.3.4:443)');
  lines.push('行為: HTTPS GET 請求');
  lines.push('建議: ✅ Allow Once');
  lines.push('');
  lines.push('寫完檔案後回覆 NO_REPLY。');
  
  return lines.join('\n');
}

/**
 * Send analysis to all Telegram users via CLI with inline buttons
 */
function sendToAllUsers(analysisText) {
  lastMessageIds = {};
  lastMessageContent = analysisText;
  
  const buttons = '[[{"text":"✅ Always Allow","callback_data":"lulu:allow"},{"text":"✅ Allow Once","callback_data":"lulu:allow-once"}],[{"text":"❌ Always Block","callback_data":"lulu:block"},{"text":"❌ Block Once","callback_data":"lulu:block-once"}]]';
  
  for (const id of CONFIG.telegramIds) {
    try {
      const escapedMessage = analysisText.replace(/'/g, "'\\''");
      const cmd = `openclaw message send --channel telegram --target ${id} --message '${escapedMessage}' --buttons '${buttons}'`;
      const output = execSync(cmd, { encoding: 'utf8', timeout: 15000, stdio: 'pipe' });
      
      // Extract message ID from CLI output
      const match = output.match(/Message ID:\s*(\d+)/i);
      if (match) {
        lastMessageIds[id] = match[1];
        debug('Sent to', id, '-> msg', match[1]);
      } else {
        log('⚠️ Sent to', id, 'but could not extract message ID');
        debug('CLI output:', output);
      }
    } catch (e) {
      log('❌ Failed to send to', id, ':', e.message?.substring(0, 100));
    }
  }
  
  log('📤 Sent to', Object.keys(lastMessageIds).length, '/', CONFIG.telegramIds.length, 'users');
}

/**
 * Wait for analysis file written by sub-agent
 */
function waitForAnalysis(timeoutMs = 30000) {
  return new Promise((resolve) => {
    const analysisPath = '/tmp/lulu-analysis.txt';
    const startTime = Date.now();
    
    // Clean up old file
    try { fs.unlinkSync(analysisPath); } catch (e) {}
    
    const check = () => {
      try {
        const content = fs.readFileSync(analysisPath, 'utf8').trim();
        if (content.length > 10) {
          debug('Analysis file found:', content.length, 'chars');
          try { fs.unlinkSync(analysisPath); } catch (e) {}
          resolve(content);
          return;
        }
      } catch (e) {}
      
      if (Date.now() - startTime > timeoutMs) {
        debug('Analysis file timeout');
        resolve(null);
        return;
      }
      
      setTimeout(check, 500);
    };
    check();
  });
}

/**
 * Send alert to OpenClaw for AI analysis
 * Sub-agent analyzes and writes to /tmp/lulu-analysis.txt
 * Then lulu-monitor sends to all users via CLI
 */
async function sendToGateway(message, alertHash) {
  return new Promise((resolve, reject) => {
    // Clean up old analysis file
    try { fs.unlinkSync('/tmp/lulu-analysis.txt'); } catch (e) {}
    
    const data = JSON.stringify({
      tool: 'sessions_spawn',
      args: {
        task: message,
        model: 'haiku',
        runTimeoutSeconds: 30,
        cleanup: 'delete'
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
      res.on('end', async () => {
        if (res.statusCode === 200) {
          try {
            const result = JSON.parse(body);
            if (result.ok) {
              debug('Sub-agent spawned, waiting for analysis file...');
              
              // Wait for sub-agent to write analysis
              const analysis = await waitForAnalysis(30000);
              
              if (analysis) {
                sendToAllUsers(analysis);
                log('✅ Analysis received and sent to all users');
              } else {
                log('⚠️ Analysis file not found after timeout, sub-agent may have failed');
              }
              
              resolve(true);
            } else {
              debug('Gateway returned error:', result);
              reject(new Error(result.error?.message || 'Unknown error'));
            }
          } catch (e) {
            debug('Failed to parse response:', body);
            resolve(true);
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
 * Edit a single Telegram message via CLI (tools/invoke edit doesn't work)
 */
function editSingleMessage(targetId, messageId, newMessage) {
  return new Promise((resolve) => {
    // Escape message for shell
    const escapedMessage = newMessage.replace(/'/g, "'\\''");
    const cmd = `openclaw message edit --channel telegram --target ${targetId} --message-id ${messageId} --message '${escapedMessage}'`;
    
    try {
      execSync(cmd, { encoding: 'utf8', timeout: 15000, stdio: 'pipe' });
      debug('Edit message success:', targetId, messageId);
      resolve(true);
    } catch (e) {
      debug('Edit message failed:', targetId, messageId, e.message?.substring(0, 100));
      resolve(false);
    }
  });
}

/**
 * Edit Telegram messages for all users to show result and who acted
 */
async function editTelegramMessages(action, success, actorId) {
  const isAllow = action.startsWith('allow');
  const isOnce = action.endsWith('-once');
  const statusEmoji = success ? (isAllow ? '✅' : '🚫') : '❌';
  const durationText = isOnce ? ' (本次)' : ' (永久)';
  const actorName = CONFIG.telegramNames[actorId] || actorId || 'unknown';
  const statusText = success 
    ? (isAllow ? '已允許' : '已封鎖') + durationText
    : '操作失敗';
  
  const statusLine = `\n\n${statusEmoji} ${statusText} by ${actorName}`;
  
  const editPromises = [];
  for (const id of CONFIG.telegramIds) {
    const msgId = lastMessageIds[id];
    if (!msgId) continue;
    
    let newMessage;
    if (lastMessageContent) {
      newMessage = lastMessageContent + statusLine;
    } else {
      newMessage = statusLine.trim();
    }
    
    editPromises.push(editSingleMessage(id, msgId, newMessage));
  }
  
  const results = await Promise.all(editPromises);
  return results.some(r => r);
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
          const validActions = ['allow', 'block', 'allow-once', 'block-once'];
          if (validActions.includes(action)) {
            const success = executeAction(action);
            res.writeHead(success ? 200 : 500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success, action }));
          } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid action. Use "allow", "block", "allow-once", or "block-once"' }));
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
        lastMessageIds,
        telegramIds: CONFIG.telegramIds,
        telegramNames: CONFIG.telegramNames
      }));
    } else if (req.method === 'GET' && req.url === '/logs') {
      try {
        const logFile = path.join(LOGS_DIR, 'actions.jsonl');
        const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n').slice(-50);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(lines.map(l => JSON.parse(l))));
      } catch (e) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('[]');
      }
    } else if (req.method === 'POST' && req.url === '/register-message') {
      // Sub-agent registers sent message IDs for later editing
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const { targetId, messageId, content } = JSON.parse(body);
          if (targetId && messageId) {
            lastMessageIds[targetId] = messageId;
            if (content) lastMessageContent = content;
            debug('Registered message:', targetId, '->', messageId);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
          } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'targetId and messageId required' }));
          }
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
    } else if (req.method === 'POST' && req.url === '/callback') {
      // Handle Telegram button callback
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        try {
          const { action, userId } = JSON.parse(body);
          const validActions = ['allow', 'block', 'allow-once', 'block-once'];
          if (validActions.includes(action)) {
            const success = executeAction(action);
            
            // Log the action
            logAction(null, action, userId, success);
            
            // Edit all users' Telegram messages to show who acted
            if (Object.keys(lastMessageIds).length > 0) {
              await editTelegramMessages(action, success, userId);
            }
            
            res.writeHead(success ? 200 : 500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success, action, userId, messageEdited: true }));
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
 * Supports: allow, block, allow-once, block-once
 */
function executeAction(action) {
  log(`Executing: ${action}`);
  
  const scriptMap = {
    'allow': 'click-allow.scpt',
    'block': 'click-block.scpt',
    'allow-once': 'click-allow-once.scpt',
    'block-once': 'click-block-once.scpt'
  };
  
  const scriptName = scriptMap[action];
  if (!scriptName) {
    log(`❌ Unknown action: ${action}`);
    return false;
  }
  
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

// CLI action handler - allow running as: node index.js allow|block|allow-once|block-once
const cliAction = process.argv[2];
if (['allow', 'block', 'allow-once', 'block-once'].includes(cliAction)) {
  const success = executeAction(cliAction);
  process.exit(success ? 0 : 1);
}

// Main
log('🔍 LuLu Monitor starting...');
loadLocalConfig();
loadGatewayConfig();
startCommandServer();
poll();
log('👀 Watching for LuLu alerts...');
if (CONFIG.autoExecute) {
  log('⚡ Auto-execute mode ENABLED - high confidence alerts will be handled automatically');
}
