# SecureOTA 3D Interface: Design Direction and Higgsfield Prompts

Oct 16, 2026 · @Rajendhira Prasath Saravanan

## Creative direction

The concept is **"Live current"**: firmware travels as a visible pulse of ember light, from a signing vault, through a shielded tunnel, into real ESP32 boards. Every 3D scene shows something the product actually does: sign, encrypt, deliver, verify, roll back.

**Mood:** dark carbon hardware lab at night. Machined aluminium and matte black PCBs, lit by ember-red and amber light. It should feel precise and engineered, like premium test equipment, not neon cyberpunk.

**Guardrails, from your own website rules:**

- No purple, violet or magenta anywhere: no gradients, glows or prompt words. Stay with carbon, bone white, ember red #FF2803 and amber #FF9742.
- Buttons are 8px rounded rectangles, never pills.
- Show no invented numbers in any render: no fake device counts, uptime percentages or customer logos. Any on-screen text in an image stays blurred or is a real label like "v2.5.1" or "SHA-256 verified".
- No emoji, no em dashes in copy, no vague hero lines.
- No AI-slop look: avoid floating random holograms, glowing brains, robots, padlocks made of light, and stock "hacker in hoodie" imagery.

**Motion rules.** Your wish for a fully 3D, animated interface sits next to your rule against over-the-top scroll and cursor animation. Both hold if the 3D lives in the media, not in the page mechanics:

- 3D motion comes from Higgsfield video loops and still renders placed as section backgrounds and feature visuals.
- The page itself scrolls normally: no scroll-jacking, no pinned scroll scenes, no cursor followers or magnetic buttons.
- UI motion is limited to fades of 150 to 250 ms, hover lifts of 2 to 4 px, and live data changing.
- With `prefers-reduced-motion`, every video becomes its poster still.

## Inspiration: where to look and what to take

Collect references for one idea each (lighting, material, layout, data display). Don't copy a whole composition, and don't reuse another designer's assets or likeness. Save 5 to 8 pins per board, then pick 2 per category.

| Platform | Search terms | What to take from it |
| --- | --- | --- |
| Pinterest | "dark hardware product render", "PCB macro photography", "industrial UI dashboard dark", "orange accent dark UI" | Lighting and material mood: rim light on aluminium, shallow depth of field on chips |
| Dribbble | "IoT dashboard dark", "device fleet management UI", "firmware update UI", "bento grid dashboard" | Layout of dense data: card grids, status chips, tables that stay readable |
| Behance | "3D product visualization electronics", "isometric server render", "tech brand identity orange black" | Full 3D scene direction, camera angles, brand systems built on one accent colour |
| Awwwards and Godly | "developer tools", "infrastructure", "security" categories | Hero composition, type scale and restraint on sites aimed at engineers |
| ArtStation | "hard surface sci-fi console", "circuit board environment" | Material detail for close-up hero frames (machined edges, connectors, solder) |
| Mobbin | "settings", "tables", "empty states", "onboarding" | Real, shipped patterns for the console pages, not just pretty shots |

**Two boards to build:**

1. *Scene board:* ESP32 boards on dark aluminium, light tunnels, vault doors, cable macro shots, smoke-free dark studio lighting.
2. *Interface board:* dark dashboards with one warm accent, status tables, timeline and pipeline views, monospace data, 8px corners.

Reject a reference if it relies on purple glow, chrome text, lens-flare spam, or fake metrics.

## Visual system

Keep the console's existing tokens so new art drops in without a redesign.

| Role | Value | Use |
| --- | --- | --- |
| Background | #0D0D0D carbon | Page and video backdrops |
| Surface | #212121 graphite | Cards, panels |
| Text | #FFFFFF / bone #F0F0EE | Body and headings |
| Primary | #FF2803 ember | Firmware pulse, primary buttons, live state |
| Secondary | #FF9742 amber | Warnings, updating state, secondary light |
| Error | #C02000 deep ember | Failed, quarantined |
| Light theme | #F6F4F1 paper, #181818 ink | Same art, lighter frame |

**Type:** a geometric grotesk for headings (Space Grotesk or Inter Tight, 600), Inter for body, JetBrains Mono for versions, hashes and COM ports.

**Materials in every render:** matte black PCB with gold pads, brushed and bead-blasted aluminium, smoked glass, braided black USB cable, small ember LEDs.

**Lighting:** one strong ember key light from low side, amber rim light, everything else falls to black. Volumetric light only as a thin beam, never fog filling the frame.

**Camera:** 50 to 85 mm lens look, shallow depth of field, slow dolly or orbit at 5 to 10 degrees per loop, no fast cuts.

**Recurring motifs (use them across pages):**

- *The pulse:* a short ember light packet travelling along a copper trace or fibre.
- *The seal:* a thin ring of light that closes around a chip when a signature verifies.
- *The vault:* a machined aluminium block with a slot, where signing keys live.
- *The tunnel:* a narrow corridor of light lines from the cloud to the board.

## Home page

The home page tells one story top to bottom: a firmware build leaves your computer, is sealed, crosses the internet and lands safely on a board. Asset codes (V1, I1 and so on) match the prompts below.

| # | Section | Components | Asset |
| --- | --- | --- | --- |
| 1 | Top bar | Logo, links (Product, Security, Docs), Sign in, primary button "Open console" (8px corners) | none |
| 2 | Hero | Headline "Signed, encrypted firmware updates for ESP32 fleets", one-line subhead, two buttons, small row of real facts (RSA-2048 signatures, AES-256 packages, automatic rollback) | V1 looping video, I1 poster still |
| 3 | How it works | Four numbered steps in a row: Build and sign, Publish, Deliver over the air, Verify or roll back. Each step has a short caption | I2, I3, I4, I5 (one square render per step) |
| 4 | Security model | Bento grid of 5 cards: signed manifests, encrypted packages, anti-rollback counter, device tokens, health quarantine. One large card carries the video | V2 in the large card, I6 for the anti-rollback card |
| 5 | The console | A real screenshot of your Devices page inside a dark device frame, with 3 callouts pointing at real features | I7 frame render (screenshot composited later, never generated) |
| 6 | First board in minutes | Three steps: plug in USB, flash from the browser, board joins the fleet. Code-style chips for COM7, v2.5.1 | V3 short loop, I8 still |
| 7 | Hardware | ESP32, ESP32-S3, ESP32-C3 shown as product renders with their real names | I9 |
| 8 | Final call to action | One sentence, one button, dark band with the pulse running behind | V4 subtle loop |
| 9 | Footer | Links, Privacy, Terms, contact, GitHub | none |

**Component notes:**

- Hero video sits behind a 60% carbon gradient on the left so the headline stays readable (contrast at least 4.5:1).
- Step and bento cards: #212121 surface, 1px border at 12% white, 12px radius, 2 to 4 px lift on hover, no tilt.
- The fact row under the hero states capabilities only. It shows no counts of users, devices or uptime.

## Console pages

Inside the console, the data is the hero. 3D art appears only as a header band or in empty states, so tables and live status stay fast and readable.

| Page | Layout and components | 3D asset |
| --- | --- | --- |
| Login | Split screen: sign-in card on the left (Clerk), animated scene on the right | V5 loop, I10 poster |
| Dashboard | Stat tiles (Devices, Online, Offline, Update available), rollout progress, latest release card, recent events list | I11 thin header band (static) |
| Devices | Stat tiles, Flash over USB card, Set up a new board stepper, device table with status chips | I12 empty state when no devices are registered |
| Releases | Stat tiles, Publish card, release cards with version, size, SHA-256 and status | I13 empty state when nothing is published |
| Deployments | Rollout timeline per release, per-device state (queued, downloading, verifying, confirmed, rolled back) | none, data only |
| Security (key vault, manifest, ASH monitor) | Key fingerprints in monospace, health score per device, quarantine list | I14 small vault illustration in the page header |
| Event logs | Filter bar, severity chips, virtualised list | none |
| Privacy and Terms | Plain reading layout, 68 characters per line | none |

**Shared components:**

- *Stat tile:* label, large tabular number, one-line hint, 3px tone rule on the left. Already built in the console.
- *Status chip:* Online, Offline, Updating, Failed, Quarantined. 6px radius, icon plus text, never colour alone.
- *Stepper:* numbered cards that show Waiting, Running, Done or Failed. Already built for board setup.
- *Empty state:* 3D still on the left, one sentence and one action on the right.
- *Live dot:* a 6px ember dot that pulses once per real event, not on a timer.

## Higgsfield image prompts

Paste the style line after every prompt and the negative line into the negative field, so all assets look like one set. Generate 4 variations, keep the best, then upscale.

**Style line (append to every prompt):**

```
photoreal 3D product render, dark carbon studio #0D0D0D, single ember-red #FF2803 key light from low left, amber #FF9742 rim light, matte black PCB with gold pads, brushed aluminium, shallow depth of field, 85mm lens, high detail, clean composition, generous negative space on the left for text
```

**Negative line:**

```
purple, violet, magenta, neon pink, rainbow, lens flare, fog, smoke, people, hands, robots, padlock icon, shield icon, glowing brain, holographic globe, readable text, fake numbers, logos, watermark, plastic toy look, cluttered, cartoon
```

**I1. Hero poster (16:9).** Same frame as the first frame of V1.

```
an ESP32 development board standing on a machined aluminium plinth, a thin line of ember light arriving along a copper trace and entering the chip, a faint ring of light closing around the chip, dark lab behind, board placed on the right third
```

**I2. Build and sign (1:1).**

```
a milled aluminium block with a narrow slot, a small black card with gold contacts sliding in, an ember seal of light pressed onto a glowing firmware chip beside it
```

**I3. Publish (1:1).**

```
a stack of three thin smoked-glass plates floating above a dark plinth, each plate etched with faint circuit lines, the top plate lit by an ember edge light, labelled only by light, no text
```

**I4. Deliver over the air (1:1).**

```
a narrow tunnel made of parallel thin light lines receding into darkness, a single ember packet of light travelling through it toward an ESP32 board at the near end
```

**I5. Verify or roll back (1:1).**

```
two identical ESP32 chips side by side on black PCB, the left one sealed by a closed ring of ember light, the right one dimmed with an amber ring half open, symmetrical composition
```

**I6. Anti-rollback counter (4:3).**

```
a macro of a mechanical counter with machined aluminium wheels, wheels only turning forward, an ember light catching the edge of the wheels, black background
```

**I7. Console device frame (16:10).**

```
a thin dark laptop with a blank matte black screen, three-quarter view on dark aluminium desk, soft ember reflection on the base, screen completely empty for a later screenshot
```

**I8. First board (16:9).**

```
an ESP32 board connected by a braided black USB cable, the cable carrying a moving ember pulse toward the board, one small LED on the board glowing amber
```

**I9. Hardware family (21:9).**

```
three ESP32 development boards of slightly different sizes laid out in a row on dark aluminium, evenly spaced, top-down three-quarter angle, each lit by a soft ember rim light
```

**I10. Login poster (3:4).**

```
close-up of a vault door made of machined aluminium rings, a narrow ember light line around the seam, perfectly centered, deep black surroundings
```

**I11. Dashboard header band (6:1).**

```
extreme wide macro of a black circuit board surface, copper traces running horizontally, a few traces carrying faint ember light, very dark, low contrast so text can sit on top
```

**I12. Devices empty state (4:3).**

```
a single unplugged ESP32 board resting on dark aluminium with a coiled black USB cable beside it, calm, waiting, soft amber light
```

**I13. Releases empty state (4:3).**

```
an empty smoked-glass tray on a dark plinth, one faint ember outline where a firmware chip would sit
```

**I14. Key vault header (3:1).**

```
a row of small machined aluminium key slots, one slot lit from inside with ember light, the rest dark, shallow depth of field
```

## Higgsfield video prompts

The best workflow is image to video: generate the still first (I1, I4, I8, I10), then animate it, so the first frame matches the poster exactly. Keep loops 6 to 8 seconds, slow camera, and make the last frame return to the first so the loop is seamless. Use the same negative line as the images, plus: `fast cuts, camera shake, flicker, morphing objects`.

**V1. Hero loop (16:9, 8 s, from I1).**

```
slow dolly in of 5 percent toward the ESP32 board on the aluminium plinth, a thin ember light packet travels along the copper trace and enters the chip, a ring of light closes around the chip and fades, the trace dims, the loop returns to the start frame, dark studio, ember key light, amber rim light, photoreal, smooth, seamless loop
```

**V2. Security bento loop (1:1, 6 s, from I5).**

```
static camera, the left chip's ring of ember light closes and pulses once, the right chip's amber ring tries to close, stops halfway and fades out, both reset to the start, minimal motion, photoreal, seamless loop
```

**V3. First board loop (16:9, 6 s, from I8).**

```
slow orbit of 8 degrees around the ESP32 board, an ember pulse runs along the braided USB cable into the board, the onboard LED blinks amber twice, orbit returns to start, shallow depth of field, seamless loop
```

**V4. Call to action band (21:9, 8 s, from I4).**

```
locked camera inside the tunnel of thin light lines, ember light packets travel slowly from far to near at even intervals, very low contrast so text can sit on top, seamless loop
```

**V5. Login loop (3:4, 8 s, from I10).**

```
the machined aluminium rings of the vault door rotate slowly in opposite directions, the ember seam light brightens as they align, then dims as they return to the start position, centered, static camera, seamless loop
```

**Optional V6. 20 to 30 second brand film** for your IEEE presentation or a project demo. Shots in order: (1) the vault seals a firmware chip, (2) the light packet enters the tunnel, (3) it reaches a row of boards, (4) one board refuses a tampered packet with an amber flash, (5) all boards show a sealed ember ring. Generate each shot as its own 5 second clip from its own still, then cut them together in an editor.

## Production checklist

The site is served from your PC through the Cloudflare tunnel, so every megabyte matters: keep each video small and give every one a still.

| Asset type | Export | Size budget |
| --- | --- | --- |
| Hero and band videos (V1, V4) | 1920x1080 WebM (VP9) plus MP4 (H.264) fallback, no audio, 24 fps | Under 3 MB each |
| Card and login videos (V2, V3, V5) | 1080 px on the long side, WebM plus MP4 | Under 1.5 MB each |
| Posters and stills | WebP, quality 80, same size as the video | Under 250 KB |
| Step and empty-state images | WebP 1200 px, plus a 600 px version for phones | Under 150 KB |

- [ ] Generate I1 to I14 with the shared style and negative lines; reject any image with purple, readable fake text or numbers.
- [ ] Animate I1, I4, I5, I8, I10 into V1 to V5 and check that each loop has no visible jump.
- [ ] Place the hero files where the console already looks for them: `apps/web/public/backgrounds/loop.webm`, `loop.mp4` and `loop.jpg` (the live wallpaper requests these today and gets 404).
- [ ] Put the other assets in `apps/web/public/media/` with the asset code in the name, for example `v2-security.webm`.
- [ ] Videos: `autoplay muted loop playsinline preload="none"` with a poster, loaded only when near the viewport.
- [ ] With `prefers-reduced-motion: reduce`, show the poster and do not load the video.
- [ ] Overlay text keeps a contrast of at least 4.5:1; add the carbon gradient where it does not.
- [ ] Every image has alt text that describes what it shows, for example "ESP32 board receiving a signed update".
- [ ] Check the light theme: stills sit inside a dark rounded frame so they still read on paper white.
- [ ] Composite the real console screenshot into I7; never ship a generated screen.
