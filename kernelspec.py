import json
import logging
import os
import pathlib
import platform
import shutil
import sys

import binaryninja as bn

from .kernelrun import get_runner_path


class _KernelSpecInstallError(Exception):
    pass


def _find_python_path() -> str:
    path = os.path.abspath(os.path.join(os.__file__, '..', '..', '..', 'bin', 'python3'))
    if os.path.exists(path):
        return path
    path = shutil.which('python3')
    if os.path.exists(path):
        return path
    path = bn.Settings().get_string('python.binaryOverride')
    if os.path.exists(path):
        return path
    raise _KernelSpecInstallError('cannot determine python executable path')


def _find_binary_ninja_executable() -> str:
    path = sys.executable
    if path is None or len(path) == 0:
        raise _KernelSpecInstallError('cannot find path to binary ninja executable')
    return path


def _find_jupyter_kernels_dir() -> str:
    system = platform.system()
    if system == 'Darwin':
        return os.path.join(pathlib.Path().home(), 'Library', 'Jupyter', 'kernels')
    elif system == 'Linux':
        return os.path.join(pathlib.Path().home(), '.local', 'share', 'jupyter', 'kernels')
    elif system == 'Windows':
        return os.path.expandvars('%APPDATA%\\jupyter\\kernels')
    raise _KernelSpecInstallError(f'unknown system {system}')


def _install_kernel_spec(overwrite: bool = False):
    python_path = _find_python_path()
    runner_script = get_runner_path()
    binary_ninja_executable = _find_binary_ninja_executable()
    kernels_dir = _find_jupyter_kernels_dir()
    config = {
        'argv': [
            python_path, runner_script, binary_ninja_executable, '{connection_file}'
        ],
        'display_name': 'Binary Ninja',
        'interrupt_mode': 'message',
        'language': "python"
    }
    logging.info(f'ipybinja installing kernel config, python_path={python_path}, runner_script={runner_script}, '
                 f'binary_ninja_executable={binary_ninja_executable}, kernels_dir={kernels_dir}, config={config}')
    os.makedirs(kernels_dir, exist_ok=True)
    if not os.path.isdir(kernels_dir):
        raise Exception(f'jupyter kernels directory, {kernels_dir} is not a directory')

    kernel_config_dir = os.path.join(kernels_dir, 'ipybinja')
    if os.path.exists(kernel_config_dir) and not overwrite:
        raise FileExistsError
    if not os.path.exists(kernel_config_dir):
        os.mkdir(kernel_config_dir)
    with open(os.path.join(kernel_config_dir, 'kernel.json'), mode='w') as f:
        json.dump(config, f)


class InstallKernelSpecTask(bn.BackgroundTaskThread):
    _MSG_BOX_TITLE = 'IPyBinja Jupyter Kernel Spec Installer'

    def __init__(self):
        super().__init__('Installing Jupyter Kernel Configuration')
        self._overwrite = False

    def _show_message(self, msg: str, is_error: bool = True):
        bn.interaction.show_message_box(
            self._MSG_BOX_TITLE,
            text=msg,
            icon=bn.MessageBoxIcon.ErrorIcon if is_error else bn.MessageBoxIcon.InformationIcon
        )

    def _get_user_confirmation(self, msg: str):
        selected = bn.interaction.show_message_box(
            self._MSG_BOX_TITLE,
            text=msg,
            buttons=bn.MessageBoxButtonSet.YesNoButtonSet,
            icon=bn.MessageBoxIcon.QuestionIcon
        )
        return selected == bn.MessageBoxButtonResult.YesButton

    def _handle_install_error(self, e: BaseException):
        if isinstance(e, FileExistsError):
            assert self._overwrite is False
            if not self._get_user_confirmation(f'Configuration directory {e} already exists, do you want to overwrite'):
                self._show_message('Installation cancelled')
                return
            self._overwrite = True
            self._do_install()
        elif isinstance(e, _KernelSpecInstallError):
            self._show_message(f'Installation failed, error: {e}')
        else:
            self._show_message(f'Installation failed with unknown error, {e}')

    def _do_install(self):
        try:
            _install_kernel_spec(self._overwrite)
            self._show_message('Installation Complete', is_error=False)
        except BaseException as e:
            self._handle_install_error(e)

    def run(self):
        self._do_install()
