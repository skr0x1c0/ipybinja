import logging
import sys
import shlex

from typing import Optional

import binaryninja as bn
import binaryninjaui as bnui

from IPython.core.magic import Magics, magics_class, line_magic
from .user_ns import _BinjaMagicVariablesProvider
from .utils import detect_python_path


class _NavMagicError(Exception):
    pass


@magics_class
class NavMagic(Magics):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._binja_ns = _BinjaMagicVariablesProvider()

    @classmethod
    def _parse_int(cls, arg: str, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
        try:
            result = int(arg)
        except ValueError:
            raise _NavMagicError(f'arg "{arg}" must be an integer')
        if min_val is not None and result < min_val:
            raise _NavMagicError(f'arg "{arg}" must be at least {min_val}')
        if max_val is not None and result > max_val:
            raise _NavMagicError(f'arg "{arg}" must be less than {max_val}')
        return result

    def _navi(self, arg: str):
        fn = self._binja_ns.current_il_function
        if fn is None:
            raise _NavMagicError(f'current_il_function is None')
        instr_index = self._parse_int(arg, min_val=0, max_val=len(fn)-1)
        vl = self._binja_ns.current_ui_view_location
        if vl is None:
            raise _NavMagicError(f'current_ui_view_location is None')
        vl.setInstrIndex(instr_index)
        self._update_view_location(vl)

    @line_magic
    def navi(self, parameter_s=''):
        try:
            self._navi(parameter_s)
        except _NavMagicError as e:
            logging.error(e)

    def _navb(self, arg: str):
        current_function = self._binja_ns.current_il_function or self._binja_ns.current_function
        if current_function is None:
            raise _NavMagicError(f'current_il_function and current_function is None')
        block_index = self._parse_int(arg, min_val=0, max_val=len(current_function.basic_blocks) - 1)
        view_location = self._binja_ns.current_ui_view_location
        if view_location is None:
            raise _NavMagicError(f'current_ui_view_location is None')
        if isinstance(current_function, bn.Function):
            view_location.setOffset(current_function.basic_blocks[block_index].start)
        else:
            view_location.setInstrIndex(current_function.basic_blocks[block_index].start)
        self._update_view_location(view_location)

    @line_magic
    def navb(self, parameter_s=''):
        try:
            self._navb(parameter_s)
        except _NavMagicError as e:
            logging.error(e)

    def _update_view_location(self, vl: bnui.ViewLocation) -> bool:
        view = self._binja_ns.current_ui_view
        if view is None:
            return False
        bn.execute_on_main_thread_and_wait(lambda: view.navigateToViewLocation(vl))
        return True


@magics_class
class PackagingMagics(Magics):
    
    @line_magic
    def pip(self, line):
        python = detect_python_path()
        if python is None:
            print(f'Error: failed to detect path to python binary. Configure python.binaryOverride setting in Binary Ninja to fix this problem')
            return
        
        if sys.platform == "win32":
            python = '"' + python + '"'
        else:
            python = shlex.quote(python)

        self.shell.system(" ".join([python, "-m", "pip", line]))

        print("Note: you may need to restart the kernel to use updated packages.")
