import getpass
import os
import shutil
import subprocess
import sys
from typing import Callable

Prompter = Callable[[str], str | None]


def _cli() -> Prompter:
    def prompt(msg: str) -> str | None:
        try:
            return getpass.getpass(msg + " ")
        except (EOFError, KeyboardInterrupt):
            return None
    return prompt


def _osascript() -> Prompter:
    def prompt(msg: str) -> str | None:
        script = (
            f'display dialog "{msg}" with title "Bitwarden" '
            f'default answer "" with hidden answer buttons {{"Cancel","OK"}} default button "OK"'
        )
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        if r.returncode != 0:
            return None
        for part in r.stdout.strip().split(","):
            if "text returned:" in part:
                return part.split("text returned:")[1].strip()
        return None
    return prompt


def _zenity() -> Prompter:
    def prompt(msg: str) -> str | None:
        r = subprocess.run(
            ["zenity", "--entry", "--hide-text", "--title", "",
             "--text", msg, "--width", "300", "--window-icon", "dialog-password"],
            capture_output=True, text=True,
        )
        return r.stdout.strip() or None if r.returncode == 0 else None
    return prompt


def _kdialog() -> Prompter:
    def prompt(msg: str) -> str | None:
        r = subprocess.run(
            ["kdialog", "--password", msg, "--title", "Bitwarden"],
            capture_output=True, text=True,
        )
        return r.stdout.strip() or None if r.returncode == 0 else None
    return prompt


def _ssh_askpass() -> Prompter:
    binary = os.environ.get("SSH_ASKPASS") or shutil.which("ssh-askpass")
    if not binary:
        raise RuntimeError("SSH_ASKPASS not set and ssh-askpass not found")

    def prompt(msg: str) -> str | None:
        r = subprocess.run([binary, msg], capture_output=True, text=True)
        return r.stdout.strip() or None if r.returncode == 0 else None
    return prompt


PROVIDERS = {
    "cli": _cli,
    "osascript": _osascript,
    "zenity": _zenity,
    "kdialog": _kdialog,
    "ssh-askpass": _ssh_askpass,
}


def get_prompter(name: str | None = None) -> Prompter:
    if name:
        if name not in PROVIDERS:
            raise ValueError(f"unknown provider: {name} (available: {', '.join(PROVIDERS)})")
        return PROVIDERS[name]()

    if sys.platform == "darwin":
        return _osascript()
    for gui in ("zenity", "kdialog"):
        if shutil.which(gui):
            return PROVIDERS[gui]()
    return _cli()


def available() -> list[str]:
    found = ["cli"]
    if sys.platform == "darwin":
        found.append("osascript")
    for name in ("zenity", "kdialog"):
        if shutil.which(name):
            found.append(name)
    if shutil.which("ssh-askpass") or "SSH_ASKPASS" in os.environ:
        found.append("ssh-askpass")
    return found
