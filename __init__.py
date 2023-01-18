# Based on https://github.com/eset/ipyida

import asyncio
import logging
import os
import sys
import types
import threading
import signal
import ctypes
import dataclasses

from typing import Optional
from concurrent.futures import ThreadPoolExecutor

import jupyter_client.session
import qasync

import binaryninja as bn
import traitlets

from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import QApplication, QVBoxLayout
from binaryninjaui import GlobalAreaWidget, GlobalArea
from binaryninja import PluginCommand
from ipykernel.kernelapp import IPKernelApp
from ipykernel.ipkernel import IPythonKernel, ZMQInteractiveShell
from jupyter_client.connect import KernelConnectionInfo
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
from qtconsole.manager import QtKernelManager, QtKernelManagerMixin
from qtconsole.client import QtKernelClient
from qtconsole.styles import default_dark_style_sheet, default_dark_syntax_style

from .user_ns import UserNamespaceProvider
from .os_router import BinjaExceptionHookRouter
from .magic_functions import NavMagic, PackagingMagics
from .kernelspec import InstallKernelSpecTask
from .kernelrun import read_env_connection_config, ConnectionConfig


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

    async def _update_ns_and_run(self, *args, cell_id, **kwargs):
        assert cell_id is not None
        session = cell_id['session']
        ipybinja_client = cell_id['ipybinja_client']
        remote_client_id = session if not ipybinja_client else None
        self.user_ns.update_magic_snapshot(remote_client_id)
        return await super().run_cell_async(*args, **kwargs, cell_id=cell_id['cellId'])

    async def run_cell_async(self, *args, **kwargs) -> ExecutionResult:
        loop = asyncio.get_running_loop()
        future = asyncio.ensure_future(loop.run_in_executor(
            self._executor,
            asyncio.run,
            self._update_ns_and_run(*args, **kwargs)
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

    async def execute_request(self, stream, ident, parent):
        # HACK: Extract information from message to pass to shell
        # This information is used by shell to ID remote clients
        metadata = parent.setdefault("metadata", {})
        metadata['cellId'] = {
            'cellId': metadata.get('cellId', None),
            'session': parent.get('header', {}).get('session'),
            'ipybinja_client': parent.get('header', {}).get('ipybinjaClient', False)
        }
        return await super().execute_request(stream, ident, parent)


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
    def apply_env_connection_config(cls, kernel: IPKernelApp) -> bool:
        config = read_env_connection_config()
        if config is None:
            return False
        kernel_config: KernelConnectionInfo = {}
        for k, v in dataclasses.asdict(config).items():
            if v is not None and k != 'file':
                kernel_config[k] = v
        kernel.connection_file = config.file or "kernel-%s.json" % os.getpid()
        kernel.load_connection_info(kernel_config)
        return True

    @classmethod
    def _create_app(cls) -> IPKernelApp:
        cls._configure_venv()
        cls._configure_path()
        app = IPKernelApp.instance(
            kernel_class=f'{__name__}.ThreadedKernel',
            outstream_class=f'{__name__}.os_router.BinjaStdOutRouter',
            displayhook_class=f'{__name__}.os_router.BinjaDisplayHookRouter',
            # We provide our own logger here because the default one from
            # traitlets adds a handler that expect stderr to be a regular
            # file object
            log=logging.getLogger("ipybinja_kernel"),
            user_ns=UserNamespaceProvider(),
            exec_files=cls._get_exec_files()
        )
        cls.apply_env_connection_config(app)
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
    
    @property
    def config(self) -> ConnectionConfig:
        config = ConnectionConfig(
            file=self.app.abs_connection_file,
            ip=str(self.app.ip),
            key=self.app.session.key.decode(),
            transport=str(self.app.transport),
            hb_port=self.app.hb_port,
            iopub_port=self.app.iopub_port,
            shell_port=self.app.shell_port,
            stdin_port=self.app.stdin_port,
            control_port=self.app.control_port,
            signature_scheme=self.app.session.signature_scheme,
            kernel_name=str(self.app.kernel_name),
        )
        return config


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


class CustomKernelClientSession(jupyter_client.session.Session):

    def msg_header(self, *args, **kwargs):
        header = super().msg_header(*args, **kwargs)
        # Used by the kernel to determine if message is from embedded
        # IPython console
        header['ipybinjaClient'] = True
        return header


class CustomKernelClient(QtKernelClient):
    session = traitlets.Instance(f'{__name__}.CustomKernelClientSession')


class CustomKernelManager(QtKernelManager):
    client_class = traitlets.DottedObjectName(f'{__name__}.CustomKernelClient')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, session=CustomKernelClientSession())


class IPythonWidget(GlobalAreaWidget):
    def __init__(self, name):
        super(IPythonWidget, self).__init__(name)
        self.kernel = IPythonKernelApp()
        self.layout = QVBoxLayout()
        self.layout.addWidget(self._create_widget())
        self.setLayout(self.layout)
        self._thread_id = threading.current_thread().native_id

    def _create_widget(self) -> RichJupyterWidget:
        self.kernel_manager = CustomKernelManager()
        config = self.kernel.config
        self.kernel_manager.ip = config.ip
        self.kernel_manager.stdin_port = config.stdin_port
        self.kernel_manager.control_port = config.control_port
        self.kernel_manager.hb_port = config.hb_port
        self.kernel_manager.session.signature_scheme = config.signature_scheme
        self.kernel_manager.session.key = config.key.encode()
        self.kernel_manager.shell_port = config.shell_port
        self.kernel_manager.transport = config.transport
        self.kernel_manager.iopub_port = config.iopub_port
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
