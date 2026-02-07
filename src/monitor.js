/**
 * LuLu Alert Monitor
 * Monitors for LuLu Firewall alerts and forwards to OpenClaw
 */

const { execSync, spawn } = require('child_process');
const path = require('path');

class LuLuMonitor {
  constructor(options = {}) {
    this.pollInterval = options.pollInterval || 1000; // 1 second
    this.verbose = options.verbose || false;
    this.lastAlertHash = null;
    this.polling = false;
    this.pendingAlerts = new Map(); // Track alerts we've sent to OpenClaw
  }

  log(...args) {
    if (this.verbose) {
      console.log(`[${new Date().toISOString()}]`, ...args);
    }
  }

  /**
   * Check if LuLu alert window exists
   */
  checkForAlert() {
    try {
      const script = `
        tell application "System Events"
          if exists process "LuLu" then
            tell process "LuLu"
              set alertWindows to (windows whose name contains "Alert")
              if (count of alertWindows) > 0 then
                return "ALERT_FOUND"
              end if
            end tell
          end if
          return "NO_ALERT"
        end tell
      `;
      const result = execSync(`osascript -e '${script}'`, { encoding: 'utf8' }).trim();
      return result === 'ALERT_FOUND';
    } catch (e) {
      return false;
    }
  }

  /**
   * Extract all text from LuLu alert window
   */
  extractAlertData() {
    try {
      const script = `
        tell application "System Events"
          tell process "LuLu"
            set alertWindow to first window whose name contains "Alert"
            set allTexts to {}
            
            -- Get all static text elements
            set textElements to every static text of alertWindow
            repeat with t in textElements
              set end of allTexts to (value of t as text)
            end repeat
            
            -- Also check groups for nested text
            try
              set groups to every group of alertWindow
              repeat with g in groups
                set groupTexts to every static text of g
                repeat with gt in groupTexts
                  set end of allTexts to (value of gt as text)
                end repeat
              end repeat
            end try
            
            -- Return as newline-separated
            set AppleScript's text item delimiters to "|||"
            return allTexts as text
          end tell
        end tell
      `;
      const result = execSync(`osascript -e '${script}'`, { encoding: 'utf8' }).trim();
      const texts = result.split('|||').filter(t => t.trim());
      return {
        texts,
        hash: this.hashTexts(texts),
        timestamp: Date.now()
      };
    } catch (e) {
      this.log('Error extracting alert data:', e.message);
      return null;
    }
  }

  /**
   * Create a hash of alert texts to detect duplicates
   */
  hashTexts(texts) {
    return texts.join('|').substring(0, 200);
  }

  /**
   * Send alert to OpenClaw for analysis
   */
  async sendToOpenClaw(alertData) {
    const message = this.formatAlertMessage(alertData);
    this.log('Sending to OpenClaw:', message.substring(0, 100) + '...');
    
    try {
      // Use openclaw CLI to send message
      const proc = spawn('openclaw', ['send', '--session', 'main', message], {
        stdio: ['ignore', 'pipe', 'pipe']
      });
      
      let stdout = '';
      let stderr = '';
      
      proc.stdout.on('data', (data) => { stdout += data; });
      proc.stderr.on('data', (data) => { stderr += data; });
      
      return new Promise((resolve, reject) => {
        proc.on('close', (code) => {
          if (code === 0) {
            this.log('Sent to OpenClaw successfully');
            resolve(true);
          } else {
            this.log('OpenClaw send failed:', stderr);
            // Fallback: try wake event
            this.sendViaWake(alertData).then(resolve).catch(reject);
          }
        });
        
        proc.on('error', (err) => {
          this.log('OpenClaw spawn error:', err.message);
          this.sendViaWake(alertData).then(resolve).catch(reject);
        });
      });
    } catch (e) {
      this.log('Error sending to OpenClaw:', e.message);
      return this.sendViaWake(alertData);
    }
  }

  /**
   * Fallback: send via wake event file
   */
  async sendViaWake(alertData) {
    const message = this.formatAlertMessage(alertData);
    const wakeFile = path.join(process.env.HOME, '.openclaw', 'wake-event.txt');
    
    try {
      require('fs').writeFileSync(wakeFile, message);
      this.log('Wrote wake event file');
      return true;
    } catch (e) {
      this.log('Failed to write wake event:', e.message);
      return false;
    }
  }

  /**
   * Format alert data as message for OpenClaw
   */
  formatAlertMessage(alertData) {
    const lines = [
      '🔥 **LuLu Firewall Alert**',
      '',
      'A network connection alert needs your attention.',
      '',
      '**Raw alert data:**',
      '```',
      ...alertData.texts,
      '```',
      '',
      'Please analyze this connection and tell me whether to Allow or Block.',
      'After deciding, I will click the appropriate button.',
      '',
      `Alert ID: ${alertData.hash.substring(0, 20)}`
    ];
    return lines.join('\n');
  }

  /**
   * Execute action on LuLu alert (Allow or Block)
   */
  executeAction(action) {
    const buttonName = action.toLowerCase() === 'allow' ? 'Allow' : 'Block';
    this.log(`Executing action: ${buttonName}`);
    
    try {
      const script = `
        tell application "System Events"
          tell process "LuLu"
            set alertWindow to first window whose name contains "Alert"
            click button "${buttonName}" of alertWindow
          end tell
        end tell
      `;
      execSync(`osascript -e '${script}'`);
      this.log(`Clicked ${buttonName} successfully`);
      return true;
    } catch (e) {
      this.log(`Failed to click ${buttonName}:`, e.message);
      return false;
    }
  }

  /**
   * Main polling loop
   */
  async poll() {
    if (!this.polling) return;

    try {
      const hasAlert = this.checkForAlert();
      
      if (hasAlert) {
        const alertData = this.extractAlertData();
        
        if (alertData && alertData.hash !== this.lastAlertHash) {
          this.log('New alert detected!');
          this.lastAlertHash = alertData.hash;
          
          // Send to OpenClaw
          await this.sendToOpenClaw(alertData);
        }
      } else {
        // Alert dismissed, reset hash
        if (this.lastAlertHash) {
          this.log('Alert dismissed');
          this.lastAlertHash = null;
        }
      }
    } catch (e) {
      this.log('Poll error:', e.message);
    }

    // Schedule next poll
    setTimeout(() => this.poll(), this.pollInterval);
  }

  /**
   * Start monitoring
   */
  start() {
    console.log('🔍 LuLu Monitor started');
    console.log(`   Poll interval: ${this.pollInterval}ms`);
    console.log('   Waiting for LuLu alerts...\n');
    
    this.polling = true;
    this.poll();
  }

  /**
   * Stop monitoring
   */
  stop() {
    console.log('🛑 LuLu Monitor stopped');
    this.polling = false;
  }
}

module.exports = LuLuMonitor;
