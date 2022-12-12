# Based on https://github.com/eset/ipyida

import asyncio
import logging
import os
import sys
import types
import threading
import signal
import ctypes

from typing import Optional
from concurrent.futures import ThreadPoolExecutor

import qasync

import binaryninja as bn

from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import QApplication, QVBoxLayout
from binaryninjaui import GlobalAreaWidget, GlobalArea
from binaryninja import PluginCommand
from ipykernel.kernelapp import IPKernelApp
from ipykernel.ipkernel import IPythonKernel, ZMQInteractiveShell
from IPython.core.interactiveshell import ExecutionResult

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
from .magic_functions import NavMagic, PackagingMagics
from .kernelspec import InstallKernelSpecTask


class ZMQThreadedShell(ZMQInteractiveShell):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tid = None
        self._executor = ThreadPoolExecutor(1, 'CustomShell', initializer=self._thread_initializer)
        # Prevents kernel from crashing with attribute not found error when a magic command fails
        self._last_traceback = None

    def _thread_initializer(self):
        self._tid = threading.current_thread().ident

    def should_run_async(self, raw_cell: str, *, transformed_cell=None, preprocessing_exc_tuple=None):
        if not self.autoawait:
            return False
        if preprocessing_exc_tuple is not None:
            return False
        return True

    async def run_cell_async(self, *args, **kwargs) -> ExecutionResult:
        self.user_ns.update_magic_snapshot()
        loop = asyncio.get_running_loop()
        future = asyncio.ensure_future(loop.run_in_executor(
            self._executor,
            asyncio.run,
            super().run_cell_async(*args, **kwargs)
        ))

        # Raise KeyboardInterrupt on executor thread when we receive SIGINT
        def sigint_handler(*_):
            if ctypes.pythonapi.PyThreadState_SetAsyncExc(
                    ctypes.c_long(self._tid), ctypes.py_object(KeyboardInterrupt)
            ) != 1:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(self._tid), None)

        handler_orig = signal.signal(signal.SIGINT, sigint_handler)
        try:
            return await future
        finally:
            signal.signal(signal.SIGINT, handler_orig)


class ThreadedKernel(IPythonKernel):
    shell_class = ZMQThreadedShell


class IPythonKernelApp:

    def __init__(self):
        if IPKernelApp.initialized():
            self.app = IPKernelApp.instance()
        else:
            self.app = IPythonKernelApp._create_app()
        self.connection_file = self.app.abs_connection_file
    
    @classmethod
    def _configure_venv(cls):
        if 'VIRTUAL_ENV' in os.environ:
            logging.debug(f'skipping configure_venv since VIRTUAL_ENV env var is set')
            return
        site_packages = bn.Settings().get_string('python.virtualenv', None)
        if site_packages is None:
            logging.debug(f'skipping configure_venv since python.virtualenv is None')
            return
        if sys.platform == "win32":
            venv = os.path.abspath(os.path.join(site_packages, '..', '..'))
        else:
            venv = os.path.abspath(os.path.join(site_packages, '..', '..', '..'))
        os.environ['VIRTUAL_ENV'] = venv
        
    @classmethod
    def _configure_path(cls):
        python_binary = bn.Settings().get_string('python.binaryOverride')
        site_packages = bn.Settings().get_string('python.virtualenv')
        if site_packages is None or python_binary is None:
            logging.debug('skipping configure_path since python.virtualenv or '
                          'python.binaryOverride is None')
            return
        binary_dir = os.path.dirname(python_binary)
        os.environ['PATH'] = f'{binary_dir}{os.pathsep}{os.environ["PATH"]}'
        logging.debug(f'configure_path modified PATH to {os.environ["PATH"]}')

    @classmethod
    def _create_app(cls) -> IPKernelApp:
        cls._configure_venv()
        cls._configure_path()
        app = IPKernelApp.instance(
            kernel_class='ipybinja.ThreadedKernel',
            outstream_class='ipybinja.os_router.BinjaStdOutRouter',
            displayhook_class='ipybinja.os_router.BinjaDisplayHookRouter',
            # We provide our own logger here because the default one from
            # traitlets adds a handler that expect stderr to be a regular
            # file object
            log=logging.getLogger("ipybinja_kernel"),
            user_ns=UserNamespaceProvider(),
            exec_files=cls._get_exec_files()
        )
        connection_file = cls._get_env_connection_file()
        if connection_file is not None:
            logging.warning(f'using IPyConsole connection file {connection_file} from '
                            f'IPYTHON_BINJA_CONNECTION_FILE env variable')
            app.connection_file = connection_file
        app.initialize()
        app.shell.set_completer_frame()
        app.shell.register_magics(NavMagic, PackagingMagics)
        app.kernel.start()
        sys.excepthook = BinjaExceptionHookRouter(app.shell.excepthook)
        return app

    @classmethod
    def _get_exec_files(cls) -> list[str]:
        user_dir = bn.user_directory()
        if user_dir is not None:
            ipybinja = os.path.join(user_dir, 'ipybinja.py')
            startup = os.path.join(user_dir, 'startup.py')
            scripts = []
            if os.path.exists(ipybinja):
                scripts.append(ipybinja)
            if os.path.exists(startup):
                scripts.append(startup)
            else:
                logging.warning(f'startup.py not found in Binary Ninja user home dir {user_dir}')
            return scripts
        logging.warning(f'Failed to get Binary Ninja user directory')
        return []

    @classmethod
    def _get_env_connection_file(cls) -> Optional[str]:
        return os.environ.get('IPYTHON_BINJA_CONNECTION_FILE', None)


class BinjaRichJupyterWidget(RichJupyterWidget):
    
    def eventFilter(self, obj, event):
        # Workaround for handling cases when Ctrl-C event
        # is not received on KeyPress
        if event.type() == QEvent.KeyRelease and \
            self._control_key_down(event.modifiers(), include_command=False) and \
            event.key() == Qt.Key_C and \
            self._executing:
                self.interrupt_kernel()
                return True
        return super().eventFilter(obj, event)

    # noinspection PyMethodMayBeStatic
    def interrupt_kernel(self):
        signal.raise_signal(signal.SIGINT)


class IPythonWidget(GlobalAreaWidget):
    def __init__(self, name):
        super(IPythonWidget, self).__init__(name)
        self.kernel = IPythonKernelApp()
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

GlobalArea.addWidget(
    lambda _: IPythonWidget('IPython Console')
)

PluginCommand.register(
    'IPyBinja\\Install Jupyter Kernel',
    'Install jupyter kernel configuration for Binary Ninja',
    lambda _: InstallKernelSpecTask().start(),
    lambda _: True
)
