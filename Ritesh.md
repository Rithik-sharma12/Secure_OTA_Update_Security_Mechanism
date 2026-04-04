## Security Layers 

```
┌──────────────────────────────────────────┐
│         Zero Internet Dependencies       │
│                                          │
│  AES-256      → aes_key (injected)       │
│  HMAC-SHA256  → hmac_key (injected)      │
│  Packet Counter → NVS (on device)        │
│  MAC Registry → IDE local DB             │
│                                          │
│  None of these need:                     │
│   Internet                               │
│   NTP server                             │
│   Time synchronization                   │
│   Any external service                   │
│                                          │
│  Works perfectly on a completely         │
│  isolated local network                  │
└──────────────────────────────────────────┘
```
## What happens in HMAC
```
┌─────────────────────────────────────────────┐
│           Key Generation & Storage          │
│                                             │
│  AT FLASH TIME (in your IDE):               │
│                                             │
│  1. IDE generates a unique 256-bit          │
│     secret key for THIS specific device     │
│                                             │
│  2. Key is injected into the tracking       │
│     agent as a #define at preprocessing:    │
│     #define HMAC_SECRET "a3f9...e12b"       │
│                                             │
│  3. Same key is stored in the IDE's         │
│     local device registry:                  │
│     { mac: "AA:BB:CC", key: "a3f9...e12b" } │
│                                             │
│  Result:                                    │
│  Device knows the key                       │
│  IDE knows the key                          │
│  Attacker does NOT know the key             │
└─────────────────────────────────────────────┘
```