# Based on https://github.com/eset/ipyida

import asyncio
import logging
import os
import sys
import types
from typing import Optional

import ipykernel.iostream
import qasync
from PySide6.QtWidgets import QApplication, QVBoxLayout
from binaryninja.scriptingprovider import ScriptingInstance, PythonScriptingInstance, original_stdout, \
    original_stderr, _PythonScriptingInstanceOutput
from binaryninjaui import GlobalAreaWidget, GlobalArea
from ipykernel.kernelapp import IPKernelApp

# Hack required for bundled PySide6 to work with QtPy
sys.modules["PySide6.QtOpenGL"] = types.ModuleType("EmptyQtOpenGL")
sys.modules["PySide6.QtOpenGLWidgets"] = types.ModuleType("EmptyQtOpenGLWidgets")
sys.modules["PySide6.QtOpenGLWidgets"].QOpenGLWidget = types.ModuleType("EmptyQOpenGLWidget")
sys.modules["PySide6.QtPrintSupport"] = types.ModuleType("EmptyQtPrintSupport")
sys.modules["PySide6.QtPrintSupport"].QPageSetupDialog = types.ModuleType("EmptyQPageSetupDialog")
sys.modules["PySide6.QtPrintSupport"].QPrintDialog = types.ModuleType("EmptyQPageSetupDialog")
os.environ["QT_API"] = "PySide6"

from qtconsole.rich_jupyter_widget import RichJupyterWidget
from qtconsole.manager import QtKernelManager
from qtconsole.client import QtKernelClient
from jupyter_client import find_connection_file
from qtconsole.styles import default_dark_style_sheet, default_dark_syntax_style


class BinjaMagicVariablesProvider(dict):
    _MAGIC_VARIABLES = {
        'current_thread',
        'current_view',
        'bv',
        'current_function',
        'current_basic_block',
        'current_llil',
        'current_mlil',
        'current_hlil',
        'dbg',
        'current_data_var',
        'current_symbol',
        'current_symbols',
        'current_segment',
        'current_sections',
        'current_comment',
        'current_ui_context',
        'current_ui_view_frame',
        'current_ui_view',
        'current_ui_action_handler',
        'current_ui_view_location',
        'current_ui_action_context',
        'current_token',
        'current_variable',
        'get_selected_data',
        'write_at_cursor',
        'current_il_index',
        'current_il_function',
        'current_il_instruction',
        'current_il_basic_block'
    }

    def __init__(self, mapping=(), **kwargs):
        super().__init__(mapping, **kwargs)
        providers = [provider for provider in ScriptingInstance._registered_instances \
                     if isinstance(provider, PythonScriptingInstance)]
        assert len(providers) == 1
        self._interpreter = providers[0].interpreter
        for k in BinjaMagicVariablesProvider._MAGIC_VARIABLES:
            super().__setitem__(k, None)

    def __getitem__(self, k):
        if k in BinjaMagicVariablesProvider._MAGIC_VARIABLES:
            self._interpreter.update_locals()
            return self._interpreter.locals[k]
        return super().__getitem__(k)

    def __setitem__(self, k, v):
        assert k not in BinjaMagicVariablesProvider._MAGIC_VARIABLES
        return super().__setitem__(k, v)

    def __delitem__(self, k):
        assert k not in BinjaMagicVariablesProvider._MAGIC_VARIABLES
        return super().__delitem__(k)

    def get(self, k, default=None):
        if k in BinjaMagicVariablesProvider._MAGIC_VARIABLES:
            self._interpreter.update_locals()
            return self._interpreter.locals.get(k, default)
        return super().get(k, default)

    def setdefault(self, k, default=None):
        assert k not in BinjaMagicVariablesProvider._MAGIC_VARIABLES
        return super().setdefault(k, default)

    def pop(self, k, v=object()):
        assert k not in BinjaMagicVariablesProvider._MAGIC_VARIABLES
        return super().pop(k, v)

    def update(self, mapping=(), **kwargs):
        super().update(mapping, **kwargs)

    def __contains__(self, k):
        return super().__contains__(k)

    def __iter__(self):
        return super().__iter__()

    def keys(self):
        return super().keys()

    def copy(self):
        return type(self)(self)

    @classmethod
    def fromkeys(cls, keys, v=None):
        return super(BinjaMagicVariablesProvider, cls).fromkeys((k for k in keys), v)

    def __repr__(self):
        return '{0}({1})'.format(type(self).__name__, super(BinjaMagicVariablesProvider, self).__repr__())


class BinjaRichJupyterWidget(RichJupyterWidget):
    pass


class BinjaTeeOutStream(ipykernel.iostream.OutStream):

    def __init__(self, *args, **kwargs):
        super(BinjaTeeOutStream, self).__init__(*args, **kwargs)
        if self.name == 'stdout':
            self._ostream = _PythonScriptingInstanceOutput(original_stdout, False)
        elif self.name == 'stderr':
            self._ostream = _PythonScriptingInstanceOutput(original_stderr, True)
        else:
            self._ostream = None

    def _setup_stream_redirects(self, name):
        backup_streams = sys.stdout, sys.stderr
        try:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            return super(BinjaTeeOutStream, self)._setup_stream_redirects(name)
        finally:
            sys.stdout, sys.stderr = backup_streams

    def write(self, string: str) -> Optional[int]:
        if self._ostream:
            self._ostream.write(string)
        return super(BinjaTeeOutStream, self).write(string)


class IPythonKernel:

    def __init__(self):
        if IPKernelApp.initialized():
            self.app = IPKernelApp.instance()
        else:
            self.app = IPythonKernel._create_app()
        self.app.shell.set_completer_frame()
        self.app.kernel.start()
        self.connection_file = self.app.connection_file

    @classmethod
    def _create_app(cls) -> IPKernelApp:
        app = IPKernelApp.instance(
            outstream_class='ipybinja.BinjaTeeOutStream',
            # We provide our own logger here because the default one from
            # traitlets adds a handler that expect stderr to be a regular
            # file object
            log=logging.getLogger("ipybinja_kernel"),
            user_ns=BinjaMagicVariablesProvider(),
        )
        app.initialize()
        return app


class IPythonWidget(GlobalAreaWidget):
    def __init__(self, name):
        super(IPythonWidget, self).__init__(name)
        self._original_excepthook = sys.excepthook
        self.kernel = IPythonKernel()
        self._ipython_excepthook = sys.excepthook
        sys.excepthook = self._excepthook_wrapper
        layout = QVBoxLayout()
        layout.addWidget(self._create_widget())
        self.setLayout(layout)

    def _create_widget(self) -> RichJupyterWidget:
        connection_file = find_connection_file(self.kernel.connection_file)
        self.kernel_manager = QtKernelManager(connection_file=connection_file)
        self.kernel_manager.load_connection_file()
        self.kernel_manager.client_factory = QtKernelClient
        self.kernel_client = self.kernel_manager.client()
        self.kernel_client.start_channels()
        widget = BinjaRichJupyterWidget(
            self,
            style_sheet=default_dark_style_sheet,
            syntax_style=default_dark_syntax_style
        )
        widget.kernel_manager = self.kernel_manager
        widget.kernel_client = self.kernel_client
        return widget

    def _excepthook_wrapper(self, *args, **kwargs):
        self._original_excepthook(*args, **kwargs)
        self._ipython_excepthook(*args, **kwargs)


if not isinstance(asyncio.get_event_loop(), qasync.QEventLoop):
    qapp = QApplication.instance()
    loop = qasync.QEventLoop(qapp, already_running=True)
    asyncio.set_event_loop(loop)
GlobalArea.addWidget(lambda context: IPythonWidget("IPython Console"))
