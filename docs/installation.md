# Installing as a Service

## macOS (launchd)

### Install files

```bash
sudo mkdir -p /opt/ai-proxy/logs
sudo cp bin/proxy /opt/ai-proxy/proxy
sudo cp proxy-config.json /opt/ai-proxy/proxy-config.json
sudo chown -R $USER /opt/ai-proxy
```

### Create the plist

Create `~/Library/LaunchAgents/com.ai-proxy.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ai-proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/ai-proxy/proxy</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/opt/ai-proxy</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/opt/ai-proxy/logs/proxy.out.log</string>
    <key>StandardErrorPath</key>
    <string>/opt/ai-proxy/logs/proxy.err.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <!-- Prevent launchd from passing shell proxy vars to the process.
             The proxy reads UPSTREAM_PROXY from proxy-config.json instead. -->
        <key>HTTP_PROXY</key>
        <string></string>
        <key>HTTPS_PROXY</key>
        <string></string>
        <key>http_proxy</key>
        <string></string>
        <key>https_proxy</key>
        <string></string>
        <key>NO_PROXY</key>
        <string></string>
    </dict>
</dict>
</plist>
```

> **Why clear the proxy env vars?** launchd can inherit `HTTP_PROXY`/`HTTPS_PROXY` from a prior
> login session. If those vars point at the proxy itself (as they do for clients), the proxy would
> route its own upstream connections back through itself, causing a loop. The
> `EnvironmentVariables` dict overrides them to empty strings so the process always starts clean.
> Configure an upstream proxy via `upstreamProxy` in `proxy-config.json` if needed.

### Load and manage

```bash
launchctl load ~/Library/LaunchAgents/com.ai-proxy.plist

# Management
launchctl stop com.ai-proxy      # stop
launchctl start com.ai-proxy     # start
launchctl unload ~/Library/LaunchAgents/com.ai-proxy.plist  # disable
```

### Verify startup

After loading the agent, confirm the proxy is running and reachable:

```bash
# Check launchd status (PID should be non-zero)
launchctl list | grep ai-proxy

# Check the management API
curl -sf http://localhost:8081/status | python3 -m json.tool

# Quick smoke-test: proxy a public HTTPS request
curl -x http://localhost:8080 -sf https://httpbin.org/get -o /dev/null -w "%{http_code}\n"
# Expected: 200

# Tail logs for startup errors
tail -f /opt/ai-proxy/logs/proxy.err.log
```

If the PID column is empty or `-`, check the error log for the exit code. Exit code 78
(`EX_CONFIG`) typically means the process cannot write to its stderr log — see the
[Log rotation](#log-rotation-newsyslog) section below.

### Log rotation (newsyslog)

Without a rotation config, `newsyslog` recreates rotated log files owned by `root`, which the
proxy process (running as your user) cannot write to. This causes an exit at startup with code 78
(`EX_CONFIG`) and a crash loop that is difficult to diagnose.

Create `/etc/newsyslog.d/ai-proxy.conf` (requires `sudo`):

```
# logfile                              owner:group    mode count  size  when  flags
/opt/ai-proxy/logs/proxy.err.log       earlplak:admin  644   5    [ADDRESS_8eddb379]     *     GZ
/opt/ai-proxy/logs/proxy.out.log       earlplak:admin  644   5    [ADDRESS_8eddb379]     *     GZ
```

Replace `earlplak` with your macOS username. The `G` flag compresses rotated files with gzip;
`Z` signals the process after rotation (not required for file-based logging but harmless).

Verify the config is valid:

```bash
sudo newsyslog -nv
```

---

## Linux (systemd)

systemd writes logs to the journal — no log files to manage. Create
`/etc/systemd/system/ai-proxy.service`:

```ini
[Unit]
Description=AI Anonymizing Proxy
After=network.target

[Service]
Type=simple
ExecStart=/opt/ai-proxy/proxy
WorkingDirectory=/opt/ai-proxy
Restart=always
RestartSec=5
User=ai-proxy
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp bin/proxy /opt/ai-proxy/proxy
sudo cp proxy-config.json /opt/ai-proxy/proxy-config.json
sudo useradd -r -s /usr/sbin/nologin ai-proxy
sudo chown -R ai-proxy:ai-proxy /opt/ai-proxy

sudo systemctl daemon-reload
sudo systemctl enable --now ai-proxy

# Management
sudo systemctl status ai-proxy
sudo journalctl -u ai-proxy -f    # tail logs
```

---

## Windows (NSSM or Task Scheduler)

**Using NSSM (recommended):**

```powershell
# Install NSSM: https://nssm.cc or `choco install nssm`
nssm install ai-proxy C:\ai-proxy\proxy.exe
nssm set ai-proxy AppDirectory C:\ai-proxy
nssm set ai-proxy AppStdout C:\ai-proxy\logs\proxy.out.log
nssm set ai-proxy AppStderr C:\ai-proxy\logs\proxy.err.log
nssm start ai-proxy

# Management
nssm stop ai-proxy
nssm start ai-proxy
nssm remove ai-proxy confirm      # uninstall
```

**Using Task Scheduler (no extra tools):**

```powershell
$action = New-ScheduledTaskAction `
    -Execute "C:\ai-proxy\proxy.exe" `
    -WorkingDirectory "C:\ai-proxy"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Seconds 10)
Register-ScheduledTask -TaskName "ai-proxy" -Action $action -Trigger $trigger -Settings $settings

# Management
Stop-ScheduledTask -TaskName "ai-proxy"
Start-ScheduledTask -TaskName "ai-proxy"
Unregister-ScheduledTask -TaskName "ai-proxy" -Confirm:$false  # remove
```
