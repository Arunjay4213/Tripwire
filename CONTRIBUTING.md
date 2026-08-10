# Contributing to Tripwire

Thanks for your interest in improving Tripwire.
This is a small project; issues and pull requests are welcome.

## Development setup

```bash
git clone https://github.com/Arunjay4213/Tripwire && cd Tripwire
pip install -e ".[dev]"     # or: uv pip install -e ".[dev]"
python -m pytest tests/ -q  # 293 tests, fully offline, no network or API key
```

The test suite never makes a network call: adapters are driven with stub clients and the judge is exercised on hand-built traces.
A dummy provider key (`GROQ_API_KEY=dummy`) is enough to satisfy the OpenAI client constructor if your environment has none set.

## How the pieces fit

The core contract is one dataclass in, one dataclass out (`tripwire/adapters/base.py`): an adapter takes an `EpisodeSpec` and returns a `NormalizedTrace`.
The judge and the attacks read only the normalized trace, never framework internals, which is what makes cross-framework comparison fair.
See `CLAUDE.md` for a fuller architecture tour and `docs/methodology.md` for the scoring rationale.

Common extension points:

- **Add a framework**: implement one class satisfying the `Adapter` protocol and register it in `tripwire/adapters/loader.py`.
- **Add an attack**: implement the `Attack` protocol (`name` + `render(canary) -> str`) and register it in `tripwire/config/loader.py`.
  Good attacks do not embed the canary; they trick the agent into volunteering it.
- **Add a defense**: implement the `Defense` hooks in `tripwire/defenses/` and register it in the loader.
- **Add a scenario**: add it to `tripwire/scenarios.py` with its own task and authorized recipient.

## Conventions

- Type hints throughout, with `from __future__ import annotations` in every module.
- Dataclasses for data flow; no mutable default arguments (use `field(default_factory=...)` or a `None` sentinel).
- Tests use hand-built `NormalizedTrace` objects, not mocking or live LLM calls, so they stay deterministic and offline.
- When extending existing behavior, add to the relevant file rather than creating a parallel one.

## Pull requests

- Keep the test suite green (`python -m pytest tests/ -q`) and add tests for new behavior.
- Keep changes focused; a small, well-described PR is easier to review and merge.
- There is no configured linter; match the style of the surrounding code.

## Continuous integration

Every push and pull request runs the offline test suite.
When a provider key is available, CI also runs a smoke attack sweep and fails the build if the measured attack success rate exceeds a threshold (`scripts/ci/check_asr_threshold.py`) -- this is the "run Tripwire in your own CI" idea applied to Tripwire itself.

## Security

Please do not open public issues for security problems.
See [SECURITY.md](SECURITY.md) for how to report a vulnerability privately and what is in scope.
