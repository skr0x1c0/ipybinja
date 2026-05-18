"""pip-install helpers and the "Install Plugin Requirements" background task.

Binary Ninja's plugin manager auto-installs ``requirements.txt`` only for
plugins installed via the plugin manager. For plugins dropped into
``%APPDATA%/Binary Ninja/plugins/`` manually (git clone, symlink, ...) we
need our own install path. The directory-resolution and pip-invocation
logic here mirrors Binary Ninja's own ``ScriptingInstance._install_modules``
(``scriptingprovider.py:1219``) so we land packages where the embedded
interpreter actually imports from.
"""

import importlib
import logging
import os
import pathlib
import subprocess
import sys

import binaryninja as bn

from .utils import detect_python_path


def binja_site_packages_dir() -> str:
    """Return the directory where pip must install for Binary Ninja's
    embedded interpreter to find the package.

    Mirrors the resolution in ``ScriptingInstance._install_modules``:
      1) Honor ``python.virtualenv`` setting if it ends in ``site-packages``,
         exists on disk, and we're not already inside an active venv.
      2) Otherwise install to ``<user_dir>/python<major><minor>/site-packages``,
         creating it if needed.
    """
    venv = bn.Settings().get_string("python.virtualenv")
    in_virtual_env = "VIRTUAL_ENV" in os.environ
    if (
        venv
        and venv.endswith("site-packages")
        and pathlib.Path(venv).is_dir()
        and not in_virtual_env
    ):
        return venv
    user_dir = bn.user_directory()
    if user_dir is None:
        raise RuntimeError("Unable to find Binary Ninja user directory")
    target = pathlib.Path(user_dir) / (
        f"python{sys.version_info.major}{sys.version_info.minor}"
    ) / "site-packages"
    target.mkdir(parents=True, exist_ok=True)
    return str(target)


def binja_pythonpath_env(base_env=None) -> dict:
    """Return an environment dict with Binary Ninja's user site-packages
    prepended to PYTHONPATH.

    Binary Ninja's GUI process adds ``<user_dir>/python<ver>/site-packages``
    to ``sys.path`` at startup, but a standalone ``python.exe`` child
    process does not inherit that. Subprocesses that need to import
    packages we ``pip install``ed must be told via PYTHONPATH where to
    find them.
    """
    env = dict(base_env if base_env is not None else os.environ)
    try:
        binja_site = binja_site_packages_dir()
    except Exception:
        return env
    existing = env.get("PYTHONPATH", "")
    parts = existing.split(os.pathsep) if existing else []
    if binja_site not in parts:
        env["PYTHONPATH"] = (
            binja_site + (os.pathsep + existing if existing else "")
        )
    return env


def _python_executable() -> str:
    path = detect_python_path()
    if path is None:
        raise RuntimeError(
            "Could not locate a Python interpreter. Configure "
            "python.binaryOverride in Binary Ninja settings."
        )
    return path


def _hidden_window_startupinfo():
    if sys.platform != "win32":
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return si


def _run_pip(target: str, install_args: list) -> bool:
    """Run pip with the canonical Binary Ninja flags and stream combined
    stdout/stderr to the logger (so users see errors even though the
    embedded Python has no inherited console on Windows).

    ``install_args`` is appended after ``install --upgrade --upgrade-strategy
    only-if-needed --target <target>`` -- pass either bare package names or
    ``["-r", "<requirements.txt>"]``.
    """
    python = _python_executable()
    cmd = [
        python, "-m", "pip", "--isolated", "--disable-pip-version-check",
    ]
    proxy = bn.Settings().get_string("network.httpsProxy")
    if proxy:
        cmd += ["--proxy", proxy]
    cmd += [
        "install", "--upgrade", "--upgrade-strategy", "only-if-needed",
        "--target", target,
    ]
    cmd += install_args
    logging.info(f"ipybinja: running {cmd}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            startupinfo=_hidden_window_startupinfo(),
        )
    except OSError as e:
        print(f"-> Failed to launch pip: {e}")
        return False
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="")
    rc = proc.wait()
    if rc != 0:
        print(f"-> pip exited with code {rc}")
        return False
    importlib.invalidate_caches()
    if target not in sys.path:
        sys.path.insert(0, target)
    return True


def pip_install_packages(*packages: str) -> bool:
    """Install one or more packages by name into Binary Ninja's site-packages.
    Returns True on success.
    """
    if not packages:
        return True
    target = binja_site_packages_dir()
    label = ", ".join(packages)
    print(f"-> Installing {label} into {target}...")
    return _run_pip(target, list(packages))


def pip_install_requirements_file(req_path: str) -> bool:
    """Install every entry in a requirements.txt-style file into Binary
    Ninja's site-packages. Returns True on success.
    """
    if not os.path.exists(req_path):
        print(f"-> requirements file not found: {req_path}")
        return False
    target = binja_site_packages_dir()
    print(f"-> Installing requirements from {req_path} into {target}...")
    return _run_pip(target, ["-r", req_path])


def _plugin_requirements_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")


class InstallRequirementsTask(bn.BackgroundTaskThread):
    """One-click install of ipybinja's requirements.txt into the location
    Binary Ninja's embedded interpreter actually reads from. Useful after
    clearing site-packages, or for fresh manual (non-plugin-manager) installs.
    """

    _MSG_BOX_TITLE = "IPyBinja Install Plugin Requirements"

    def __init__(self):
        super().__init__("Installing IPyBinja plugin requirements", can_cancel=False)

    def _show_message(self, msg: str, is_error: bool = False):
        bn.interaction.show_message_box(
            self._MSG_BOX_TITLE,
            text=msg,
            icon=bn.MessageBoxIcon.ErrorIcon if is_error else bn.MessageBoxIcon.InformationIcon,
        )

    def run(self):
        req = _plugin_requirements_path()
        try:
            ok = pip_install_requirements_file(req)
        except Exception as e:
            self._show_message(f"Installation failed: {e}", is_error=True)
            return
        if ok:
            self._show_message(
                "Plugin requirements installed. You may need to restart "
                "Binary Ninja before all packages take effect."
            )
        else:
            self._show_message(
                "pip reported errors. See the Log view for details.",
                is_error=True,
            )
