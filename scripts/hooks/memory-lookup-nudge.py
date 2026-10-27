#!/usr/bin/env python3
"""UserPromptSubmit hook: on a human message, remind the agent to look in its memory.

The owner asked (2026-09-25, TG 16727) that an agent always look around in its
memory when a HUMAN writes, without loading any tier by default. Measured the
same day on the owner's last 30 Telegram messages: a strict FTS search built
from the message words hit 3/30, all trivial ("Mehet"); the relaxed OR form hit
30/30 with ~2400 rows each, i.e. noise; the stored nomic vectors do not separate
Hungarian text either. So this hook injects NO memory content. It injects a
short, fixed instruction with the correct search recipe, and the agent picks the
keyword (a name, a topic), which it does far better than a word list.

When it speaks: a channel message (<channel ...>) or a bare terminal prompt.
When it stays silent: inter-agent traffic (<trusted-peer>, <untrusted>,
[Uzenet @...]), scheduled tasks, the agent's own task notices, system-style
prompts that start with "[" (context guard, recovery brief, inbox nudges,
SYSTEM-DIREKTIVA), and local slash commands.

Recall mod (card 94f8d99f): in the Brainy main session, while the "elohivas"
recall mod is really active, the hook injects the candidates itself, so the
"look now" imperative is dropped and only the recipe stays (see recall_mod_active).
Every other agent, and Brainy with the mod off, gets the old text byte for byte.

Never raises and never blocks: any error is a silent exit(0). The registration
carries a 3 s timeout, and the hook does no network or DB work at all.
"""
import json
import os
import sys

MACHINE_MARKERS = (
    "<trusted-peer ",
    "<untrusted ",
    "<scheduled-task ",
    "<task-notification>",
    "[Uzenet @",
    "[Uzenet a tavoli @",
    "[Üzenet @",
    "<command-name>",
    "<local-command-",
    "<system-reminder>",
    "Base directory for this skill:",
)


def _project_root():
    # scripts/hooks/ -> project root (two dirs up)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _env_value(key, default):
    val = os.environ.get(key)
    if val:
        return val
    try:
        with open(os.path.join(_project_root(), ".env")) as f:
            for line in f:
                if line.startswith(key + "="):
                    v = line.split("=", 1)[1].strip().strip("\"'")
                    if v:
                        return v
    except Exception:
        pass
    return default


def agent_id(cwd):
    """<install>/agents/<name>[/...] -> name; the install root -> MAIN_AGENT_ID."""
    root = os.path.realpath(_project_root())
    here = os.path.realpath(cwd or "")
    agents = os.path.join(root, "agents") + os.sep
    if here.startswith(agents):
        name = here[len(agents):].split(os.sep, 1)[0]
        if name:
            return name
    return _env_value("MAIN_AGENT_ID", "marveen")


def is_human(prompt):
    text = prompt.lstrip()
    if not text:
        return False
    if any(m in prompt for m in MACHINE_MARKERS):
        return False
    if "<channel " in prompt:
        return True
    # Bare prompt: the owner typing into the terminal or the dashboard. System
    # prompts on this path are bracket-tagged, and slash commands start with "/".
    return not text.startswith("[") and not text.startswith("/")


def _is_sha12(name):
    return len(name) == 12 and all(c in "0123456789abcdef" for c in name)


def recall_mod_active(root, environ):
    """True only in the Brainy main session with the recall mod really loaded and on.

    Three conditions, all of them (anything else keeps the full old nudge):
      1. realpath(CLAUDE_CONFIG_DIR) is <root>/.channels-config (the isolated config
         root of the main session; the same self-gate as the mod's fallback);
      2. an entry of CLAUDE_CODE_PLUGIN_DIRS (":"-separated) is the frozen copy
         <root>/store/mods/elohivas/<sha12> or the live <root>/plugins/elohivas, and
         has hooks/elohivas.py;
      3. <root>/store/elohivas/DISABLE does not exist (the mod's kill switch).
    Pure path and stat work, no network, no DB."""
    try:
        cfg = environ.get("CLAUDE_CONFIG_DIR") or ""
        dirs = environ.get("CLAUDE_CODE_PLUGIN_DIRS") or ""
        if not cfg or not dirs:
            return False
        root = os.path.realpath(root)
        if os.path.realpath(cfg) != os.path.join(root, ".channels-config"):
            return False
        frozen = os.path.join(root, "store", "mods", "elohivas")
        live = os.path.join(root, "plugins", "elohivas")
        loaded = False
        for entry in dirs.split(":"):
            if not entry:
                continue
            real = os.path.realpath(entry)
            ok = real == live or (
                os.path.dirname(real) == frozen and _is_sha12(os.path.basename(real))
            )
            if ok and os.path.isfile(os.path.join(real, "hooks", "elohivas.py")):
                loaded = True
                break
        if not loaded:
            return False
        return not os.path.lexists(os.path.join(root, "store", "elohivas", "DISABLE"))
    except Exception:
        return False


def nudge(agent, port, token_path, recall_active=False):
    recipe = (
        f'curl -s -G -D /tmp/mem-fejlec-{agent}.txt -H "Authorization: Bearer $(cat {token_path})" '
        f'--data-urlencode "agent={agent}" --data-urlencode "q=KULCSSZO" "http://localhost:{port}/api/memories"\n'
        f"grep -i '^x-memory-search' /tmp/mem-fejlec-{agent}.txt  "
        "(relaxed=true = kozelites, nem bizonyitek; hiany-allitashoz: --data-urlencode \"strict=1\"; "
        "idoszak: date=tegnap | since= until=)"
    )
    if recall_active:
        return (
            "[memoria-szetnezes] Emberi uzenet. A felidezett jelolteket a rendszer a "
            "[memoria-elohivas] blokkban mar elohozta (nem bizonyitek). Ha az nem jott, vagy "
            "pontosabb emlek vagy hiany-allitas kell, a keresesi recept:\n" + recipe
        )
    return (
        "[memoria-szetnezes] Emberi uzenet: mielott valaszolsz, nezd meg, van-e rola emleked. "
        "A kulcsszot te valaszd (nev, tema), ne a mondat toltelekszavait.\n" + recipe
    )


def main():
    try:
        payload = json.load(sys.stdin)
        prompt = payload.get("prompt") or ""
        if not is_human(prompt):
            sys.exit(0)
        agent = agent_id(payload.get("cwd") or os.getcwd())
        port = _env_value("WEB_PORT", "3420")
        token_path = os.path.join(_project_root(), "store", ".dashboard-token")
        recall = recall_mod_active(_project_root(), os.environ)
        print(nudge(agent, port, token_path, recall))
    except SystemExit:
        raise
    except Exception:
        pass  # a nudge that crashes the prompt is worse than no nudge
    sys.exit(0)


if __name__ == "__main__":
    main()
