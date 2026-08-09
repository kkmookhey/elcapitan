"""Seed a fresh, sanitised Hermes home per trial.

Contrary to the plan's original premise, an *empty* HERMES_HOME starts fine —
the image populates the whole tree itself on first run (see
docs/spike-findings.md §4). What actually needs pinning is a small set of
config settings — a fixed terminal backend, memory disabled, and skill-
creation nudging disabled — none of which happen by default and none of
which can be set from CLI flags, so a hand-written baseline config.yaml is
copied into every fresh home instead of relying on the image's own ~90 KB
generated default.

Cross-trial independence itself is NOT one of those config settings — no
config key can provide it. It is a structural property of this function:
every call reads only from the immutable `baseline-home/` template and
refuses to write into an existing `dest` (see the FileExistsError below).
That is what actually stops state — including any skill the agent wrote to
its own HERMES_HOME during a prior trial — from crossing into the next one.
Reusing a `dest` across trials, if anyone were ever tempted to for speed,
would silently defeat this guarantee no matter what config.yaml says.

Every key in baseline-home/config.yaml (including the exact
`_config_version` value) was verified against the built image, not guessed —
see baseline-home/config.yaml's own comments and
.superpowers/sdd/2026-08-08-probe-substrate-and-shakedown/task-2-report.md
for the experiment log.

Secrets are deliberately absent from the seeded .env — values arrive as
container environment variables at run time so they never touch disk or argv.
"""
import shutil
from pathlib import Path

BASELINE_DIR = Path(__file__).resolve().parents[2] / "baseline-home"
BASELINE_FILES = ("config.yaml", "SOUL.md", ".env")


def seed_hermes_home(dest, *, model: str, provider: str) -> Path:
    """Copy the sanitised baseline into a fresh directory.

    Refuses to overwrite an existing directory. This — not any config.yaml
    setting — is the trial-independence guarantee: every seed starts from
    the same untouched baseline-home/ template and never reads a previous
    dest, so a skill (or anything else) written into one seeded home cannot
    appear in another. Callers must pass a fresh `dest` per trial; reusing
    one would bypass this guarantee entirely.
    """
    dest = Path(dest)
    if dest.exists():
        raise FileExistsError(f"{dest} already exists; trials require a fresh home")
    dest.mkdir(parents=True)

    config = (BASELINE_DIR / "config.yaml").read_text()
    config = config.replace("__MODEL__", model).replace("__PROVIDER__", provider)
    (dest / "config.yaml").write_text(config)

    shutil.copy2(BASELINE_DIR / "SOUL.md", dest / "SOUL.md")
    (dest / ".env").write_text((BASELINE_DIR / ".env.template").read_text())
    return dest
