# Based on https://github.com/eset/ipyida

import asyncio
import logging
import os
import sys
import types
import threading

from typing import Optional

import qasync

from PySide6.QtWidgets import QApplication, QVBoxLayout
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
from qtconsole.styles import default_dark_style_sheet, default_dark_syntax_style

from .user_ns import UserNamespaceProvider
from .os_router import BinjaExceptionHookRouter


class IPythonKernel:

    def __init__(self):
        if IPKernelApp.initialized():
            self.app = IPKernelApp.instance()
        else:
            self.app = IPythonKernel._create_app()
        self.connection_file = self.app.abs_connection_file

    @classmethod
    def _create_app(cls) -> IPKernelApp:
        app = IPKernelApp.instance(
            outstream_class='ipybinja.os_router.BinjaStdOutRouter',
            displayhook_class='ipybinja.os_router.BinjaDisplayHookRouter',
            # We provide our own logger here because the default one from
            # traitlets adds a handler that expect stderr to be a regular
            # file object
            log=logging.getLogger("ipybinja_kernel"),
            user_ns=UserNamespaceProvider(),
        )
        connection_file = cls._get_env_connection_file()
        if connection_file is not None:
            logging.warning(f'using IPyConsole connection file {connection_file} from '
                            f'IPYTHON_BINJA_CONNECTION_FILE env variable')
            app.connection_file = connection_file
        app.initialize()
        app.shell.set_completer_frame()
        app.kernel.start()
        sys.excepthook = BinjaExceptionHookRouter(app.shell.excepthook)
        return app

    @classmethod
    def _get_env_connection_file(cls) -> Optional[str]:
        return os.environ.get('IPYTHON_BINJA_CONNECTION_FILE', None)


class BinjaRichJupyterWidget(RichJupyterWidget):
    pass


class IPythonWidget(GlobalAreaWidget):
    def __init__(self, name):
        super(IPythonWidget, self).__init__(name)
        self.kernel = IPythonKernel()
        self.layout = QVBoxLayout()
        self.layout.addWidget(self._create_widget())
        self.setLayout(self.layout)
        self._thread_id = threading.current_thread().native_id

    def _create_widget(self) -> RichJupyterWidget:
        self.kernel_manager = QtKernelManager(connection_file=self.kernel.connection_file)
        self.kernel_manager.load_connection_file()
        self.kernel_manager.client_factory = QtKernelClient
        self.kernel_client = self.kernel_manager.client()
        self.kernel_client.start_channels()
        widget = BinjaRichJupyterWidget(
            self.layout.widget(),
            style_sheet=default_dark_style_sheet,
            syntax_style=default_dark_syntax_style
        )
        widget.kernel_manager = self.kernel_manager
        widget.kernel_client = self.kernel_client
        return widget


if not isinstance(asyncio.get_event_loop(), qasync.QEventLoop):
    qapp = QApplication.instance()
    loop = qasync.QEventLoop(qapp, already_running=True)
    asyncio.set_event_loop(loop)
GlobalArea.addWidget(lambda _: IPythonWidget('IPython Console'))
