import sys
import threading

from typing import Optional

from binaryninja.scriptingprovider import ScriptingInstance, PythonScriptingInstance
from binaryninja.scriptingprovider import original_stdout, original_stderr
from ipykernel.iostream import OutStream
from ipykernel.displayhook import ZMQDisplayHook


class _BinjaSysRestores:
    stdout = sys.stdout
    stderr = sys.stderr
    displayhook = sys.displayhook
    excepthook = sys.excepthook


def _is_inbuilt_console_thread():
    current_thread = threading.current_thread().ident
    # noinspection PyProtectedMember
    for instance in ScriptingInstance._registered_instances:
        if not isinstance(instance, PythonScriptingInstance):
            continue
        if instance.interpreter.ident == current_thread:
            return True
    return False


class BinjaStdOutRouter(OutStream):

    def __init__(self, *args, **kwargs):
        super(BinjaStdOutRouter, self).__init__(*args, **kwargs)
        if self.name == 'stdout':
            self._orig_stream = _BinjaSysRestores.stdout
        elif self.name == 'stderr':
            self._orig_stream = _BinjaSysRestores.stderr
        else:
            self._orig_stream = None

    def _setup_stream_redirects(self, name):
        backup_streams = sys.stdout, sys.stderr
        try:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            return super()._setup_stream_redirects(name)
        finally:
            sys.stdout, sys.stderr = backup_streams

    def write(self, string: str) -> Optional[int]:
        if self._orig_stream and _is_inbuilt_console_thread():
            return self._orig_stream.write(string)
        return super().write(string)


class BinjaDisplayHookRouter(ZMQDisplayHook):

    def __call__(self, *args, **kwargs):
        if _is_inbuilt_console_thread():
            return _BinjaSysRestores.displayhook(*args, **kwargs)
        return super().__call__(*args, **kwargs)


class BinjaExceptionHookRouter:

    def __init__(self, ipython_excepthook):
        assert ipython_excepthook is not None
        self._ipython_excepthook = ipython_excepthook

    def __call__(self, *args, **kwargs):
        if _is_inbuilt_console_thread():
            return _BinjaSysRestores.excepthook(*args, **kwargs)
        return self._ipython_excepthook(*args, **kwargs)
