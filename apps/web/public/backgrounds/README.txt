Your own animated background ("Your video" in Settings -> Appearance -> Scene)
==============================================================================

Put files with EXACTLY these names in this folder:

  loop.webm   preferred (VP9 or AV1)    - smaller, sharper
  loop.mp4    fallback  (H.264)         - for Safari / older browsers
  loop.jpg    still frame (poster)      - shown while loading and to visitors
                                          who turn on "reduce motion"

You can supply only one of the two video files; both is best.

Recommended format
------------------
  Resolution   1920x1080 (or 1280x720 for smaller files), landscape 16:9
  Length       8-20 seconds, last frame matching the first (seamless loop)
  Frame rate   24 or 30 fps
  Audio        none (it always plays muted)
  Size         aim for under 3-5 MB per file
  Look         dark and low-contrast, slow motion, no text or logos -
               it sits behind tables and cards at the "strength" you pick

Convert any clip with ffmpeg (https://ffmpeg.org):

  ffmpeg -i input.mp4 -an -vf "scale=1920:-2,fps=30" -c:v libvpx-vp9 -b:v 1500k -row-mt 1 loop.webm
  ffmpeg -i input.mp4 -an -vf "scale=1920:-2,fps=30" -c:v libx264 -crf 26 -preset slow -pix_fmt yuv420p -movflags +faststart loop.mp4
  ffmpeg -i input.mp4 -vf "scale=1920:-2" -frames:v 1 -q:v 3 loop.jpg

Only use clips you made or have the right to use (for example a clip you
generated yourself). Do not download other people's Pinterest or stock clips
without a licence.

GIF and Lottie are not supported here: GIFs are many times larger than
the same clip as WebM/MP4, and the built-in scenes already cover vector-style
motion.
