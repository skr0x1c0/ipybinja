import os
import logging
import platform

import binaryninja as bn

from typing import Optional


def _detect_python_from_os() -> Optional[str]:
    system = platform.system()
    if system == 'Darwin' or system == 'Linux':
        return os.path.abspath(os.path.join(os.path.dirname(os.__file__), '..', '..', 'bin', 'python3'))
    elif system == 'Windows':
        return os.path.abspath(os.path.join(os.path.dirname(os.__file__), '..', 'python.exe'))
    return None


def detect_python_path() -> Optional[str]:
    path = bn.Settings().get_string('python.binaryOverride')
    if path is not None and len(path) > 0:
        if os.path.exists(path):
            return path
        logging.error(f'Invalid python.binaryOverride setting {path}, path does not exist')
    path = _detect_python_from_os()
    if path is not None and os.path.exists(path):
        return path
    return None
