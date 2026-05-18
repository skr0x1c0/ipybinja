# -*- encoding: utf8 -*-
#
# Launch a Jupyter Notebook from Binary Ninja and connect it to the embedded
# IPython kernel via a per-PID proxy kernelspec. Based on ipyida's notebook.py.

import atexit
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser

import binaryninja as bn
import binaryninjaui as bnui
import nbformat
from jupyter_client import find_connection_file
from jupyter_core.paths import jupyter_data_dir, jupyter_runtime_dir

from .install import binja_pythonpath_env, binja_site_packages_dir, pip_install_packages
from .user_ns import _BinjaMagicVariablesProvider
from .utils import detect_python_path


def _notebook_major_version():
    try:
        import notebook
    except ImportError:
        return None
    try:
        return int(notebook.__version__.split('.')[0])
    except (AttributeError, ValueError):
        return None


def _list_running_servers():
    major = _notebook_major_version()
    if major is not None and major >= 7:
        from jupyter_server.serverapp import list_running_servers
    else:
        from notebook.notebookapp import list_running_servers
    return list_running_servers()


def _server_root_dir(server_info):
    return server_info.get("root_dir") or server_info.get("notebook_dir") or ""


def _python_executable():
    path = detect_python_path()
    if path is None:
        raise RuntimeError(
            "Could not locate a Python interpreter. Configure "
            "python.binaryOverride in Binary Ninja settings."
        )
    return path


def _proxy_runner_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_runner.py")


def _current_binary_path():
    """Return the path of the currently active BinaryView, or None."""
    try:
        bv = _BinjaMagicVariablesProvider().current_view
    except Exception:
        return None
    if bv is None:
        return None
    fm = getattr(bv, "file", None)
    if fm is None:
        return None
    name = getattr(fm, "filename", None)
    if name:
        return name
    return getattr(fm, "original_filename", None)


# --- Subprocess lifetime binding -------------------------------------------
# Bind the notebook subprocess to Binary Ninja's process lifetime so the OS
# kills it when Binary Ninja goes away (crash, force-kill, browser-driven
# shutdown). Windows: Job Object. Linux: PR_SET_PDEATHSIG.

if sys.platform == 'win32':
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _JobObjectExtendedLimitInformation = 9

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    ]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]

    _ipybinja_job_handle = None

    def _get_ipybinja_job():
        global _ipybinja_job_handle
        if _ipybinja_job_handle is not None:
            return _ipybinja_job_handle
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not _kernel32.SetInformationJobObject(
            job, _JobObjectExtendedLimitInformation,
            ctypes.byref(info), ctypes.sizeof(info),
        ):
            _kernel32.CloseHandle(job)
            return None
        _ipybinja_job_handle = job
        return job

    def _bind_proc_to_host_lifetime(proc):
        job = _get_ipybinja_job()
        if job is None:
            return
        handle = getattr(proc, "_handle", None)
        if handle is None:
            return
        if not _kernel32.AssignProcessToJobObject(job, int(handle)):
            err = ctypes.get_last_error()
            logging.warning(
                "AssignProcessToJobObject failed (err=%d); notebook will not "
                "be auto-killed on Binary Ninja crash", err
            )

else:
    def _bind_proc_to_host_lifetime(proc):
        pass


def _child_set_pdeathsig():
    if not sys.platform.startswith('linux'):
        return
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_SET_PDEATHSIG = 1
        SIGTERM = 15
        libc.prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0)
    except Exception:
        pass


def _popen_python(*args, **kwargs):
    python = _python_executable()
    if sys.platform == 'win32':
        si_hidden_window = subprocess.STARTUPINFO()
        si_hidden_window.dwFlags = subprocess.STARTF_USESHOWWINDOW
        si_hidden_window.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = si_hidden_window
    elif sys.platform.startswith('linux'):
        kwargs.setdefault("preexec_fn", _child_set_pdeathsig)
    kwargs.setdefault("env", binja_pythonpath_env())
    proc = subprocess.Popen([python] + list(args), **kwargs)
    _bind_proc_to_host_lifetime(proc)
    return proc


def _popen_python_module(module, *args, **kwargs):
    return _popen_python("-m", module, *args, **kwargs)


class NotebookManager(object):

    def __init__(self, connection_file):
        self.connection_file = connection_file
        self.nb_proc = None
        self.nb_pipe_thread = None
        self.nb_pipe_buffer = []
        self.nb_pipe_lock = threading.Lock()
        self._atexit_registered = False

    @staticmethod
    def ensure_kernel_proxy_installed():
        try:
            import jupyter_kernel_proxy  # noqa: F401
            return True
        except ImportError:
            return pip_install_packages("jupyter-kernel-proxy")

    @staticmethod
    def ensure_notebook_installed():
        try:
            import notebook  # noqa: F401
            return True
        except ImportError:
            return pip_install_packages("notebook")

    @staticmethod
    def ensure_psutil_installed():
        try:
            import psutil  # noqa: F401
            return True
        except ImportError:
            return pip_install_packages("psutil")

    def _kernelspec_name(self):
        return "ipybinja-%d" % os.getpid()

    @staticmethod
    def _cleanup_stale_kernelspecs():
        try:
            import psutil
        except ImportError:
            return
        kernels_dir = os.path.join(jupyter_data_dir(), "kernels")
        if not os.path.isdir(kernels_dir):
            return
        prefix = "ipybinja-"
        for name in os.listdir(kernels_dir):
            if not name.startswith(prefix):
                continue
            try:
                pid = int(name[len(prefix):])
            except ValueError:
                continue
            if pid == os.getpid():
                continue
            if psutil.pid_exists(pid):
                continue
            shutil.rmtree(os.path.join(kernels_dir, name), ignore_errors=True)

    @staticmethod
    def _cleanup_stale_jpserver_files():
        """Remove jpserver-<pid>.json runtime files whose owning process is
        dead. Binary Ninja crashing (or the job-object SIGKILL'ing the
        notebook subprocess on host exit) leaves these behind, and
        ``jupyter notebook list`` then keeps reporting dead servers
        forever. The pid is in the filename, so check it with psutil.
        """
        try:
            import psutil
        except ImportError:
            return
        runtime_dir = jupyter_runtime_dir()
        if not os.path.isdir(runtime_dir):
            return
        prefix = "jpserver-"
        suffix = ".json"
        for name in os.listdir(runtime_dir):
            if not (name.startswith(prefix) and name.endswith(suffix)):
                continue
            try:
                pid = int(name[len(prefix):-len(suffix)])
            except ValueError:
                continue
            if psutil.pid_exists(pid):
                continue
            try:
                os.remove(os.path.join(runtime_dir, name))
            except OSError:
                pass

    @staticmethod
    def _remove_jpserver_file(pid):
        if not pid:
            return
        path = os.path.join(jupyter_runtime_dir(), "jpserver-%d.json" % pid)
        try:
            os.remove(path)
        except OSError:
            pass

    def ensure_kernelspec_installed(self):
        """Install (or refresh) this Binary Ninja instance's proxy kernelspec.

        Writes ``<data_dir>/kernels/ipybinja-<pid>/kernel.json`` whose argv
        runs our proxy_runner.py as a standalone script (passing the
        plugin-local absolute path, since the ipybinja package isn't on the
        external Python's sys.path) with the kernel-file basename as
        positional argv[2].
        """
        try:
            import jupyter_kernel_proxy  # noqa: F401
        except ImportError:
            return False

        self._cleanup_stale_kernelspecs()

        spec_dir = os.path.join(
            jupyter_data_dir(), "kernels", self._kernelspec_name()
        )
        spec_path = os.path.join(spec_dir, "kernel.json")
        spec = {
            "argv": [
                _python_executable(),
                _proxy_runner_path(),
                "{connection_file}",
                os.path.basename(self.connection_file),
            ],
            "display_name": "Binary Ninja (PID %d)" % os.getpid(),
            "language": "python",
            "metadata": {"debugger": True},
            # python.exe spawned standalone by jupyter doesn't inherit
            # Binary Ninja's sys.path, and the bundled interpreter ships
            # with a _pth file that disables PYTHONPATH. proxy_runner.py
            # reads IPYBINJA_EXTRA_PATH and prepends it to sys.path before
            # ``import jupyter_kernel_proxy``.
            "env": {"IPYBINJA_EXTRA_PATH": binja_site_packages_dir()},
        }
        try:
            os.makedirs(spec_dir, exist_ok=True)
            with open(spec_path, "w") as f:
                json.dump(spec, f)
        except OSError as e:
            print("-> Could not write ipybinja kernelspec: %s" % e)
            return False
        return True

    @staticmethod
    def _server_reachable(server_info, timeout=1.0):
        """list_running_servers() yields whatever is in <jupyter_runtime_dir>
        /jpserver-*.json without verifying the server is alive. A binja
        session that crashed without removing its json leaves a stale entry
        whose URL still parses but whose port is dead. Ping /api/status to
        weed those out before we trust the entry.
        """
        base = server_info.get("url", "").rstrip("/")
        if not base:
            return False
        token = server_info.get("token", "")
        headers = {"Authorization": "token " + token} if token else {}
        try:
            req = urllib.request.Request(base + "/api/status", headers=headers)
            urllib.request.urlopen(req, timeout=timeout).read()
            return True
        except (urllib.error.URLError, OSError):
            return False

    @staticmethod
    def _path_norm(p):
        """Normalize a path for cross-format comparison: slash style, case
        (Windows), and . / .. components. Binja can hand us forward-slashed
        paths while jupyter stores ``root_dir`` after ``os.path.abspath``
        which uses native separators -- without normalization the
        ``startswith`` check below silently never matches.
        """
        if not p:
            return p
        return os.path.normcase(os.path.normpath(p))

    def _get_running_notebook_config(self, anchor_path):
        anchor_norm = self._path_norm(anchor_path)
        for server_info in _list_running_servers():
            root = _server_root_dir(server_info)
            if not root:
                continue
            if not anchor_norm.startswith(self._path_norm(root)):
                continue
            if not self._server_reachable(server_info):
                continue
            return server_info
        return None

    def _create_proxy_session(self, server_info, relative_path):
        """Pre-create a kernel session bound to this Binary Ninja's proxy
        kernel. Notebook 7's JupyterLab-based frontend ignores the legacy
        ?kernel_name= query argument; posting the session beforehand makes
        the page reuse the attached proxy kernel when it opens.
        """
        base = server_info.get("url", "").rstrip("/")
        token = server_info.get("token", "")
        if not base:
            return
        body = json.dumps({
            "path": "/".join(relative_path.split(os.path.sep)),
            "type": "notebook",
            "name": "",
            "kernel": {"name": self._kernelspec_name()},
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "token " + token
        req = urllib.request.Request(
            base + "/api/sessions", data=body, headers=headers, method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10).read()
        except (urllib.error.URLError, OSError) as e:
            print("-> Could not pre-create proxy session: %s" % e)

    def _parse_args(self, line):
        args = line.split()
        parsed = dict()
        if "--skip-dependency-checks" in args:
            parsed["skip_dependency_checks"] = True
            args.remove("--skip-dependency-checks")
        if len(args) > 0:
            parsed["filename"] = args[0]
        return parsed

    def _resolve_notebook_location(self, filename_arg):
        """Pick a directory + .ipynb filename based on current view, or fall
        back to Binary Ninja's user directory.
        """
        binary_path = _current_binary_path()
        if binary_path:
            base_dir = os.path.dirname(binary_path)
            default_stem = os.path.basename(binary_path).rsplit(".", 1)[0]
        else:
            base_dir = bn.user_directory() or os.getcwd()
            default_stem = "binja_session"
        stem = filename_arg if filename_arg else default_stem
        if not stem.endswith(".ipynb"):
            stem += ".ipynb"
        return os.path.join(base_dir, stem)

    def open_notebook(self, line):
        """Open a Jupyter Notebook connected to Binary Ninja's IPython kernel.

        Arguments:
            --skip-dependency-checks    Skip checks for notebook /
                                        jupyter-kernel-proxy / psutil
            <filename>                  Notebook filename (.ipynb optional);
                                        defaults to the current binary's name
                                        in the same directory.
        """
        args = self._parse_args(line)

        if not args.get("skip_dependency_checks", False):
            if not self.ensure_notebook_installed() or \
               not self.ensure_kernel_proxy_installed() or \
               not self.ensure_psutil_installed() or \
               not self.ensure_kernelspec_installed():
                raise Exception("Could not find or install all requirements")

        self._cleanup_stale_jpserver_files()

        ipynb_path = self._resolve_notebook_location(args.get("filename"))
        anchor_dir = os.path.dirname(ipynb_path)

        nb_server_info = self._get_running_notebook_config(anchor_dir)

        if nb_server_info is None:
            print("-> Starting notebook")
            # Binary Ninja's bundled python.exe has a _pth file that
            # ignores PYTHONPATH, so ``python -m notebook`` can't see
            # packages we installed under binja_site_packages_dir().
            # Inline a bootstrap that injects sys.path then runs the
            # ``notebook`` module via runpy.
            binja_site = binja_site_packages_dir()
            bootstrap = (
                "import sys, runpy; "
                f"sys.path.insert(0, {binja_site!r}); "
                "sys.argv[:] = ['notebook'] + sys.argv[1:]; "
                "runpy.run_module('notebook', run_name='__main__')"
            )
            self.nb_proc = _popen_python(
                "-c", bootstrap,
                "--no-browser", "-y",
                "--notebook-dir", anchor_dir,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True,
            )
            self._ensure_atexit_registered()
            # Drain stdout immediately. Otherwise the OS pipe buffer (~4KB
            # on Windows) can fill during the startup-polling window and
            # block the server's own logger -- which then never finishes
            # binding the port.
            self.nb_pipe_thread = threading.Thread(
                target=self._notebook_stdout_thread, daemon=True
            )
            self.nb_pipe_thread.start()
            try_count = 0
            while nb_server_info is None and self.nb_proc.poll() is None and try_count < 20:
                time.sleep(0.5)
                nb_server_info = self._get_running_notebook_config(anchor_dir)
                try_count += 1
            if nb_server_info is None:
                self.nb_proc.terminate()
                with self.nb_pipe_lock:
                    for s in self.nb_pipe_buffer:
                        print(s, end="")
                    self.nb_pipe_buffer = []
                raise Exception("Couldn't start Jupyter Notebook")

        if not os.path.exists(ipynb_path):
            os.makedirs(os.path.dirname(ipynb_path), exist_ok=True)
            with open(ipynb_path, "w") as f:
                nb = nbformat.versions[nbformat.current_nbformat].new_notebook()
                json.dump(nb, f)
        relative_path = os.path.relpath(ipynb_path, _server_root_dir(nb_server_info))
        # Touch the connection file so jupyter_kernel_proxy's atime-based
        # fallback selection picks ours. Primary selection is via argv[2].
        try:
            os.utime(find_connection_file(self.connection_file), None)
        except OSError:
            pass
        self._create_proxy_session(nb_server_info, relative_path)
        url = nb_server_info.get("url") + \
            "notebooks/" + "/".join(relative_path.split(os.path.sep)) + \
            '?kernel_name=' + self._kernelspec_name() + \
            '&token=' + nb_server_info.get("token")
        # Sanity-check that the server is actually reachable -- list_running_servers
        # reads jpserver-*.json files which can lag behind a server that crashed
        # right after the banner.
        base = nb_server_info.get("url", "").rstrip("/")
        token = nb_server_info.get("token", "")
        try:
            api_req = urllib.request.Request(
                base + "/api/status",
                headers={"Authorization": "token " + token} if token else {},
            )
            urllib.request.urlopen(api_req, timeout=3).read()
            reachable = True
        except (urllib.error.URLError, OSError) as e:
            reachable = False
            print(f"-> Warning: notebook server at {base} not responding: {e}")
            print(f"-> nb_proc.poll() = {self.nb_proc.poll() if self.nb_proc else 'no proc'}")
        if reachable:
            print(f"-> Opening {url}")
        webbrowser.open(url)
        return url

    def _notebook_stdout_thread(self):
        while self.nb_proc.poll() is None:
            r = self.nb_proc.stdout.readline()
            with self.nb_pipe_lock:
                self.nb_pipe_buffer.append(r)

    def notebook_log(self, line):
        "Print output from Jupyter Notebook started by IPyBinja"
        if self.nb_proc:
            with self.nb_pipe_lock:
                for s in self.nb_pipe_buffer:
                    print(s, end="")
                self.nb_pipe_buffer = []
        else:
            print("Notebook isn't running or managed by this IPyBinja instance")

    def _shutdown_server_via_api(self, timeout=3):
        if self.nb_proc is None:
            return False
        server_info = None
        try:
            for info in _list_running_servers():
                if info.get("pid") == self.nb_proc.pid:
                    server_info = info
                    break
        except Exception:
            return False
        if server_info is None:
            return False
        base = server_info.get("url", "").rstrip("/")
        if not base:
            return False
        token = server_info.get("token", "")
        headers = {}
        if token:
            headers["Authorization"] = "token " + token
        req = urllib.request.Request(
            base + "/api/shutdown", data=b"", headers=headers, method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=timeout)
        except (urllib.error.URLError, OSError):
            return False
        return True

    def _ensure_atexit_registered(self):
        # Binary Ninja's normal Quit path goes through Python shutdown, so
        # atexit handlers fire while our nb_proc is still alive -- we get
        # one shot at /api/shutdown which lets the server delete its own
        # jpserver-<pid>.json. Without this the job-object KILL_ON_JOB_CLOSE
        # SIGKILLs the notebook subprocess and the runtime file leaks,
        # leaving a dead entry in `jupyter notebook list` indefinitely.
        # (Hard binja crash still leaks, but _cleanup_stale_jpserver_files
        # sweeps those on the next %open_notebook.)
        if self._atexit_registered:
            return
        atexit.register(self._atexit_shutdown)
        self._atexit_registered = True

    def _atexit_shutdown(self):
        try:
            self.shutdown()
        except Exception:
            pass

    def shutdown(self):
        if self.nb_proc:
            nb_pid = self.nb_proc.pid
            graceful = False
            try:
                graceful = self._shutdown_server_via_api(timeout=3)
            except Exception:
                graceful = False
            if graceful:
                try:
                    self.nb_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    graceful = False
            if not graceful:
                try:
                    self.nb_proc.terminate()
                except Exception:
                    pass
                # Server didn't get a chance to delete its own runtime file.
                self._remove_jpserver_file(nb_pid)
        if self.nb_pipe_thread:
            self.nb_pipe_thread.join(timeout=2)
        spec_dir = os.path.join(
            jupyter_data_dir(), "kernels", self._kernelspec_name()
        )
        shutil.rmtree(spec_dir, ignore_errors=True)
