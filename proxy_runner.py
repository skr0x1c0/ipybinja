# -*- encoding: utf8 -*-
#
# Wrapper around jupyter_kernel_proxy that patches three behaviours:
#
# (a) KernelProxyManager._send_proxy_kernel_info is a 3-second fallback:
#     if the real kernel does not reply to kernel_info_request within
#     that window the proxy synthesises a minimal reply that lacks the
#     "debugger" field. On notebook 7 / JupyterLab the debug button is
#     enabled based on kernel_info_reply.debugger -- the fallback racing
#     the real reply silently disables it.
#
# (b) Clicking "Shutdown" / "Restart" in the JupyterLab kernel menu sends
#     a shutdown_request on the control (and historically shell) channel.
#     If we forward it, Binary Ninja's embedded ipykernel calls
#     IOLoop.stop() on the kernel's loop, which -- because qasync ties
#     asyncio to Binary Ninja's Qt event loop -- tears Binary Ninja down
#     with it. Instead we answer locally with shutdown_reply and drop the
#     message: the notebook server then terminates this proxy subprocess
#     only, and Binary Ninja's kernel keeps running.
#
# (c) connect_to_last picks the newest kernel-*.json by st_atime, which
#     is fragile after a few open/shutdown cycles. The ipybinja kernel-
#     spec passes Binary Ninja's connection-file basename as argv[2];
#     use it to dial the right kernel directly.
#
# Based on https://github.com/yufengzjj/ipyida proxy_runner.py.

import os
import sys

# Binary Ninja's bundled python.exe ships with a python<ver>._pth file that
# disables site detection and ignores PYTHONPATH. The site-packages where
# we pip-installed jupyter_kernel_proxy isn't on sys.path until we put it
# there manually. The plugin passes the directory list via this env var in
# kernel.json. Must happen BEFORE the jupyter_kernel_proxy import.
_extra = os.environ.get("IPYBINJA_EXTRA_PATH")
if _extra:
    for _p in _extra.split(os.pathsep):
        if _p and _p not in sys.path:
            sys.path.insert(0, _p)

import jupyter_kernel_proxy
from jupyter_kernel_proxy import KernelProxyManager, JupyterMessage


# --- (a) keep the JupyterLab debug button enabled -------------------------

_orig_send_proxy_kernel_info = KernelProxyManager._send_proxy_kernel_info


def _patched_send_proxy_kernel_info(self, request):
    if getattr(self.server, "proxy_target", None) is not None:
        # Real kernel will answer; do not race it with a stripped-down
        # fallback reply that drops the "debugger" flag.
        return
    return _orig_send_proxy_kernel_info(self, request)


KernelProxyManager._send_proxy_kernel_info = _patched_send_proxy_kernel_info


# --- (b) intercept browser-initiated shutdown so Binary Ninja survives ----

def _make_shutdown_interceptor(channel_name):
    def handler(server, target_stream, data):
        msg = JupyterMessage.parse(data)
        restart = (msg.content or {}).get("restart", False)
        reply_stream = getattr(server.streams, channel_name)
        reply_parts = msg.identities + server.make_multipart_message(
            "shutdown_reply",
            {"restart": restart, "status": "ok"},
            parent_header=msg.header,
        )
        reply_stream.send_multipart(reply_parts)
        reply_stream.flush()
        # Return None to drop the request -- do NOT forward to Binary Ninja's kernel.
        return None
    return handler


_orig_init = KernelProxyManager.__init__


def _patched_init(self, server):
    _orig_init(self, server)
    self.server.intercept_message(
        "control", "shutdown_request", _make_shutdown_interceptor("control"),
    )
    self.server.intercept_message(
        "shell", "shutdown_request", _make_shutdown_interceptor("shell"),
    )


KernelProxyManager.__init__ = _patched_init


# --- (c) connect deterministically to Binary Ninja's kernel ---------------

_target_kernel_file = sys.argv[2] if len(sys.argv) > 2 else None

if _target_kernel_file:
    def _patched_connect_to_last(self):
        self.update_running_kernels()
        try:
            self.connect_to(_target_kernel_file)
            return
        except ValueError:
            pass
        if self.kernels:
            self.connect_to(next(iter(self.kernels.keys())))

    KernelProxyManager.connect_to_last = _patched_connect_to_last


def main():
    if len(sys.argv) < 2:
        print("Usage: python proxy_runner.py <connection_file> [<binja_kernel_file>]")
        sys.exit(1)
    jupyter_kernel_proxy.start(sys.argv[1])


if __name__ == "__main__":
    main()
