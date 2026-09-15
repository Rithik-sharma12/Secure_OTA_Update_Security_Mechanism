# SecureOTA local agent

Gives the web dashboard access to the COM ports on the computer that is
viewing it. The dashboard is served from the cloud and cannot see USB
devices on your machine; this agent runs on your machine, listens on
`127.0.0.1:17317` only, and the dashboard page talks to it from the browser.

## Run it

```bash
python secureota_agent.py
```

The agent installs its two dependencies (pyserial, esptool) itself on first run.

Leave the window open. Open https://ota.nyx-ctf.tech/devices - connected
boards (e.g. `COM7 - Silicon Labs CP210x`) are listed automatically and can
be flashed and monitored from the page.

Optional: `python secureota_agent.py --token <secret>` makes the agent require
that token; paste it into the dashboard when asked.

The same file is served by the dashboard at `/agent/secureota_agent.py`
(a copy lives in `CODE/OTA_IDE/public/agent/` - keep both in sync).
