# Recording the demo GIF

There is no `demo.gif` in this repo yet. This file is the exact capture
script so anyone can record a real one. Do not fake a demo: a GIF must
show the actual tool running.

## What to record

A single terminal session, under 15 seconds, showing:

1. `python3 subdomain_takeover_checker.py examples/sample-dns.csv` (about 5 seconds)
2. `python3 subdomain_takeover_checker.py examples/sample-dns.csv --fail-on medium; echo "exit: $?"` (about 3 seconds)
3. `python3 subdomain_takeover_checker.py --cname blog=sajid.github.io --json` (about 3 seconds)

Keep the commands short and the output readable. No typing mistakes,
no scrolling, no extra windows.

## Capture settings

- Terminal size: **100 columns x 28 rows**
- Font: a monospace font at 14-16 pt so text stays legible at GIF size
- Theme: dark background with light text (matches the banner)
- Shell prompt: keep it short, e.g. `$`
- Working directory: the repo root, so the command is just
  `python3 subdomain_takeover_checker.py ...`

## Suggested tools

- **asciinema** (terminal recording, then convert):
  `asciinema rec demo.cast`, run the three commands, `Ctrl-D` to stop.
  Convert with `agg demo.cast demo.gif` (asciinema-agg).
- **VHS** (scripted, reproducible): write a `demo.tape` file with the
  three commands and `vhs demo.tape`. This is the recommended route
  because the tape file can be committed and re-run.
- **ScreenToGif** (Windows) or **peek** (Linux): record the terminal
  window directly, then trim to the three commands.

Example `demo.tape` for VHS:

```
Output demo.gif
Set Shell "bash"
Set FontSize 16
Set Width 1000
Set Height 560
Type "python3 subdomain_takeover_checker.py examples/sample-dns.csv"
Enter
Sleep 5s
Type "python3 subdomain_takeover_checker.py examples/sample-dns.csv --fail-on medium; echo \"exit: $?\""
Enter
Sleep 3s
Type "python3 subdomain_takeover_checker.py --cname blog=sajid.github.io --json"
Enter
Sleep 3s
```

## Size budget

- Target: **under 5 MB**, ideally under 2 MB.
- Reduce colours to 128 or fewer, drop the frame rate to 10 fps, and
  crop to the terminal window only.
- With `gifsicle`: `gifsicle -O3 --colors 128 demo.gif -o demo-small.gif`
- With `ffmpeg`: `ffmpeg -i demo.gif -vf "fps=10,scale=1000:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse" demo-small.gif`

## Publishing

1. Save the finished GIF as `assets/demo.gif` in the repo root.
2. Add it to the README directly above the Features section, in place
   of the static preview note, with alt text
   `Demo: Subdomain Takeover Checker grading the sample DNS export in the terminal`.
3. Commit the VHS tape file as `docs/demo.tape` too, so the recording
   can be reproduced.
