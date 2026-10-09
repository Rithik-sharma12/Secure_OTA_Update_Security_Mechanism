# Landing hero video — generation prompt and drop-in steps

The landing page (`CODE/OTA_IDE/app/page.tsx`) plays an optional looping
background video behind the hero. It is picked up automatically when either
file exists:

```
CODE/OTA_IDE/public/brand/hero-loop.webm   (preferred, VP9)
CODE/OTA_IDE/public/brand/hero-loop.mp4    (H.264 fallback)
```

The video sits under a dark gradient at 55 % opacity, with the animated
device-network canvas drawn on top, so it should be **dark, slow and
low-contrast**. It is never shown to visitors who ask for reduced motion.

## Prompt for Gemini (Veo)

> Cinematic, seamless looping background video, 8 seconds, 16:9, 1920×1080,
> 24 fps. Extremely slow, smooth dolly-in through deep space toward the night
> side of planet Earth seen from orbit; the continents are traced by thin,
> glowing ember-orange data lines that connect hundreds of tiny glowing
> points, like a network of devices spanning the globe. Small bright amber
> pulses travel along the lines from one central glowing node to the points,
> and faint white pulses travel back. Colour palette strictly limited to near
> black (#0d0d0d), charcoal (#212121), ember red-orange (#ff2803), amber
> (#ff9742) and soft bone white (#f0f0ee); no blue, no green, no purple.
> Most of the frame is dark: keep the left 50 % of the frame almost empty and
> black for text overlay, with the glowing planet and network on the right
> half. Subtle volumetric haze, gentle film grain, shallow depth of field,
> soft bloom on the light points. Calm, premium, technical mood. No text, no
> logos, no people, no UI, no lens flares, no fast motion, no camera shake,
> no cuts. The last frame must match the first frame so the clip loops
> seamlessly.

**Negative prompt (if your tool has the field):** text, letters, watermark,
logo, people, faces, hands, bright sky, daylight, blue tones, green tones,
purple, rainbow, fast camera movement, shaky camera, scene cuts, flicker,
strobing, cartoon, low resolution.

### Variations to try

* **Circuit board:** replace the Earth with "an extreme close-up macro shot
  of a dark microcontroller circuit board; ember-orange light pulses race
  along the copper traces into a central chip that glows softly".
* **Abstract mesh:** "a slowly rotating abstract 3D mesh of connected nodes
  floating in darkness, ember and amber light pulses travelling along the
  edges".

Keep the palette, the empty left half, the slow motion and the loop
instruction in every variation.

## After generating

Veo clips rarely loop perfectly and are larger than a background needs.
Trim, crossfade the ends and compress with ffmpeg:

```bash
# 1. Make the loop seamless: crossfade the last second into the first.
ffmpeg -i veo.mp4 -filter_complex \
  "[0]trim=0:7,setpts=PTS-STARTPTS[a];[0]trim=7:8,setpts=PTS-STARTPTS[b];[b][a]xfade=transition=fade:duration=1:offset=0[v]" \
  -map "[v]" -an loop.mp4

# 2. Web versions, muted, ~1280px wide, small enough to start instantly.
ffmpeg -i loop.mp4 -an -vf "scale=1280:-2,fps=24" -c:v libvpx-vp9 -b:v 900k -row-mt 1 \
  CODE/OTA_IDE/public/brand/hero-loop.webm
ffmpeg -i loop.mp4 -an -vf "scale=1280:-2,fps=24" -c:v libx264 -profile:v high -crf 28 \
  -preset slow -movflags +faststart -pix_fmt yuv420p CODE/OTA_IDE/public/brand/hero-loop.mp4
```

Aim for **under 3 MB each**. Commit both files; the page shows the video on
its next revalidation (60 s) or restart, fading it in once it can play.
