# Documentation index

Start with the [project README](../README.md) and the [repository tree](../Tree.md).

## Running and deploying

| Document | Contents |
|---|---|
| [how-to-run.md](how-to-run.md) | Running locally and online, step by step |
| [guides/DOCKER_DEPLOYMENT.md](guides/DOCKER_DEPLOYMENT.md) | Docker Compose stack |
| [guides/DEPLOYMENT.md](guides/DEPLOYMENT.md) | Cloud VPS deployment |
| [guides/DEPLOYMENT_MODES.md](guides/DEPLOYMENT_MODES.md) | Local, LAN and cloud modes compared |
| [guides/CLOUDFLARE_TUNNEL_SETUP.md](guides/CLOUDFLARE_TUNNEL_SETUP.md) | Public HTTPS through Cloudflare Tunnel |
| [guides/END_TO_END_DEMO.md](guides/END_TO_END_DEMO.md) | Full demo from firmware build to confirmed OTA |

## How it works

| Document | Contents |
|---|---|
| [architecture/OTA_ARCHITECTURE.md](architecture/OTA_ARCHITECTURE.md) | System and protocol architecture |
| [guides/REMOTE_OTA_AND_USB_PROVISIONING.md](guides/REMOTE_OTA_AND_USB_PROVISIONING.md) | Remote commands and USB provisioning |
| [guides/WEB_OTA_UPDATE_GUIDE.md](guides/WEB_OTA_UPDATE_GUIDE.md) | Updating from the web console |
| [architecture/ACCEPTANCE_TESTS.md](architecture/ACCEPTANCE_TESTS.md) | Acceptance checklist (run with `scripts/acceptance-test.ps1`) |

## Security

| Document | Contents |
|---|---|
| [SECURITY_REMEDIATION.md](SECURITY_REMEDIATION.md) | Past findings and secrets to rotate |
| [architecture/BACKEND_AUDIT.md](architecture/BACKEND_AUDIT.md), [architecture/BACKEND_CHECKLIST.md](architecture/BACKEND_CHECKLIST.md), [architecture/GAP_ANALYSIS.md](architecture/GAP_ANALYSIS.md) | Backend review and open gaps |
| [guides/OTA_IOT_Security_Comprehensive_Guide.md](guides/OTA_IOT_Security_Comprehensive_Guide.md), [guides/OTA_Security_Quick_Reference.md](guides/OTA_Security_Quick_Reference.md), [guides/OTA_Security_Implementation_Examples.md](guides/OTA_Security_Implementation_Examples.md) | OTA security background and references |

## Design

| Path | Contents |
|---|---|
| [design/](design) | Frontend plan, UI structure, design prompts, inspiration links |
| [images/](images) | README screenshots and the animated UX workflow |

## Other

| Path | Contents |
|---|---|
| [database/supabase_schema.sql](database/supabase_schema.sql) | Earlier Supabase schema |
| [web/](web) | Original console planning documents |
| [planning/](planning) | Knowledge requirements and report format |
| [archive/](archive) | Retired files kept for reference |
