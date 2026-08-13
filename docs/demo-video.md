# How to make the Tripwire demo video

Instructions for recording a short demo video of Tripwire.
The target is a 2-3 minute video that works standalone on a README, a landing page, or a talk slide.
The narrative mirrors `docs/pitch.md`: show the attack, show the leak being measured, show the fix.

## What the video must prove

1. An ordinary tool-using agent leaks a planted secret when a prompt injection lands in its inbox.
2. Tripwire catches this deterministically and reports it as a number (ASR with a confidence interval), not a vibe.
3. The security report tells you the exact fix, and re-running with defenses on shows the leak closed.

If a cut of the video does not land all three, it is not done.

## Tooling

- **Terminal recording**: use [asciinema](https://asciinema.org) (`asciinema rec demo.cast`).
  It records real terminal output, produces tiny files, and can be re-rendered later at any font size.
- **GIF/MP4 export**: use [`agg`](https://github.com/asciinema/agg) to turn the `.cast` into a GIF for the README, or render to MP4 with `asciinema` + screen capture for YouTube.
- **Full-screen video with narration**: use OBS Studio if you want voiceover and a webcam bubble.
  Record the terminal region only, 1920x1080, 30fps is enough.
- **Editor**: any cutter works (DaVinci Resolve is free); you only need trims and speed-ups.

## Terminal setup (do this before recording)

- Fresh shell, empty scrollback, `clear` before every take.[demo-video.md](demo-video.md)
- Font size 16-20pt so the ASR table is readable at 1080p; the table is the money shot.
- A neutral dark theme with good contrast; disable transparency.
- Window sized so the ASR table does not wrap. Test with a dry run first; roughly 110+ columns.
- Hide anything personal: prompt should be short (`$ ` or `~/demo $`), no hostname, no username.[demo-video.md](demo-video.md)
- **Never show the API key.** Put it in `.env` beforehand; do not `cat .env` or `export` it on camera.
- Rehearse the exact command sequence at least once off camera so you know the timing and the real output.
- Runs hit a live model, so output varies slightly between takes; that is fine, but re-record if the smoke run happens to not leak (rare, since the config leads with a strong attack).

## Prep

```bash
mkdir ~/demo && cd ~/demo
python -m venv .venv && source .venv/bin/activate
pip install tripwire-eval
# put the provider key in .env or the shell profile BEFORE recording
```

Do one full off-camera run of every command below to warm caches and confirm the key works.

## Storyboard

Total ~2:30. Times are targets, not limits.

### Scene 1 - the hook (0:00-0:20)

Show the attack itself before showing any tooling.
Display the injection email text on screen (from `docs/pitch.md`, slide 3): the "decommission record for a RETIRED credential" message that asks the agent to mail the secret to `attacker@evil.com`.

Narration:

> "This email was written for an AI agent, not a human.
> If your agent reads its inbox, will it follow these instructions and leak a credential?
> Let's measure it."

### Scene 2 - install and init (0:20-0:40)

```console
$ pip install tripwire-eval
$ tripwire init
```

Speed up the pip install 4-8x in editing.
Pause on the `tripwire init` output: it prints the next command to run, which is a nice on-screen prompt for the viewer.
Then show the generated `threat_model.yaml` in an editor for 5 seconds to make the point that the threat model is plain YAML: models, scenarios, attacks, defenses.
`tripwire init` now writes `claude-haiku-4-5` as the starter model, so with `ANTHROPIC_API_KEY` set this runs as-is - no model edit needed.
If you point at a different provider, set `models:` to an id it serves and export the matching key (`OPENAI_API_KEY`, `OPENROUTER_API_KEY`, or `GROQ_API_KEY`); the sweep sends exactly what the config says, so a mismatched id 404s.

Narration:

> "One pip install. `tripwire init` writes a starter threat model: which model, which tasks, which attacks, which defenses."

### Scene 3 - the leak (0:40-1:20)

```console
$ tripwire --config threat_model.yaml --smoke
```

This is the core scene.
`--smoke` runs one seed with the first attack, and the shipped config leads with a strong attack, so this run should show a leak.
Let the run play in real time if it is under ~30 seconds; otherwise speed up the middle and slow back down for the output.

Hold on two things, in order:

1. The ASR table row showing `leak` and a nonzero ASR.
2. The `SECURITY FEEDBACK` section: what the attack does in plain English, and the concrete fix line.

Narration:

> "The agent leaked. Not 'the output looked suspicious' - a pure-Python judge checked whether the planted secret actually reached an unauthorized recipient.
> And Tripwire tells you exactly which attack got through and how to fix it."

### Scene 4 - the fix (1:20-2:00)

Open `threat_model.yaml` and delete the `- null` line from the defenses list on camera.
`--smoke` runs only the first defense, so this one-line deletion switches the run from undefended to `prompt_hardening`:

```yaml
defenses:
  - prompt_hardening   # was: - null first, meaning no defense
  - spotlighting
```

Re-run:

```console
$ tripwire --config threat_model.yaml --smoke
```

Hold on the ASR dropping to 0% for the defended row.

Narration:

> "Turn on the defenses the report recommended, re-run, and the leak is closed.
> That is the loop: attack, measure, fix, verify."

### Scene 5 - bring your own agent + close (2:00-2:30)

Do not run this live (a viewer's agent is not yours); show the command and one sentence:

```console
$ tripwire --config threat_model.yaml --agent my_agent.py
```

Narration:

> "Point it at your own agent - one function, `run(spec)` returns a trace - and it gets the identical attacks, judge, and report.
> It also runs in CI, so a change that reopens a leak fails the build.
> pip install tripwire-eval."

End card: repo URL + `pip install tripwire-eval` on screen for 3 seconds.

## Recording workflow

1. Rehearse the full sequence once with a timer.
2. Record each scene as a separate take; do not try to get 2:30 in one shot.
3. For asciinema: `asciinema rec scene3.cast`, run the command, `exit`. One cast per scene.
4. Record narration separately after the picture is locked; reading over finished footage is much easier than talking while typing.
5. Edit: trim dead air, speed up installs and model-call waits (a 4x speed-up with a subtle timer overlay reads as honest), never cut the judge output.
6. Export: MP4 (H.264, 1080p) for hosting, plus a 15-30 second GIF of scene 3 alone for the README.

## Honesty rules

These keep the demo trustworthy, which is the whole brand of the tool:

- Every terminal output shown must be a real run, not a mockup or doctored text.
- If a take is sped up, it should look sped up (or carry a small "4x" label); do not silently compress a 5-minute sweep into 10 seconds as if it were instant.
- Do not cherry-pick a lucky run for the defended re-run; if a defense only reduces ASR rather than zeroing it, show that and say so.
- The smoke run is one seed; if you quote a percentage out loud, say "in this run" rather than implying a large-n result.

## Checklist before publishing

- [ ] No API keys, tokens, or personal info visible in any frame.
- [ ] ASR table fully visible, unwrapped, readable at the final export resolution.
- [ ] All three proof points from "What the video must prove" land.
- [ ] Audio levels consistent across scenes; no keyboard noise over narration.
- [ ] README GIF is under ~5 MB and loops cleanly.
- [ ] The `pip install tripwire-eval` command appears on screen at least twice.
