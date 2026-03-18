import shutil
import subprocess
import sys


def ask_password(title: str = "Bitwarden", prompt: str = "Unlock password:") -> str | None:
    if sys.platform == "darwin":
        return _osascript(title, prompt)
    if shutil.which("zenity"):
        return _zenity(title, prompt)
    return None


def _osascript(title: str, prompt: str) -> str | None:
    script = (
        f'display dialog "{prompt}" with title "{title}" '
        f'default answer "" with hidden answer buttons {{"Cancel","OK"}} default button "OK"'
    )
    r = subprocess.run(
        ["osascript", "-e", script],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None
    for part in r.stdout.strip().split(","):
        if "text returned:" in part:
            return part.split("text returned:")[1].strip()
    return None


def _zenity(title: str, prompt: str) -> str | None:
    r = subprocess.run(
        ["zenity", "--entry", "--hide-text", "--title", "", "--text", prompt,
         "--width", "300", "--window-icon", "dialog-password"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() or None if r.returncode == 0 else None
