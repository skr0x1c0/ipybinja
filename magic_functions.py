import binaryninja as bn

from logging import error

from IPython.core.magic import Magics, magics_class, line_magic
from .user_ns import _BinjaMagicVariablesProvider


@magics_class
class NavMagic(Magics):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._binja_ns = _BinjaMagicVariablesProvider()

    @line_magic
    def navi(self, parameter_s=''):
        try:
            instr_index = int(parameter_s)
        except ValueError:
            error(f'invalid arg "{parameter_s}", instruction index must be integer')
            return

        if instr_index < 0:
            error(f'invalid arg "{instr_index}", instruction index must be positive integer')
            return

        fn = self._binja_ns.current_il_function
        if fn is None:
            error(f'current view should be LLIL, MLIL or HLIL (or its variants)')
            return

        if instr_index > len(fn):
            error(f'invalid arg "{instr_index}", instruction index greater than max index {len(fn)}')
            return

        vl = self._binja_ns.current_ui_view_location
        if vl is None:
            error(f'failed to get current view location')
            return

        vl.setInstrIndex(instr_index)
        view = self._binja_ns.current_ui_view
        view.navigateToViewLocation(vl, False)

    def _nav_to_il_block(self, fn: bn.ILFunctionType, block_index: int):
        if block_index >= len(fn.basic_blocks):
            error(f'invalid arg "{block_index}", block index must be <= {len(fn.basic_blocks)}')
            return
        instr_index = fn.basic_blocks[block_index].start
        vl = self._binja_ns.current_ui_view_location
        if vl is None:
            error(f'failed to get current view location')
            return

        vl.setInstrIndex(instr_index)
        view = self._binja_ns.current_ui_view
        view.navigateToViewLocation(vl, False)

    def _nav_to_fn_block(self, fn: bn.Function, block_index: int):
        if block_index >= len(fn.basic_blocks):
            error(f'invalid arg "{block_index}", block index must be <= {len(fn.basic_blocks)}')
            return
        offset = fn.basic_blocks[block_index].start
        vl = self._binja_ns.current_ui_view_location
        if vl is None:
            error(f'failed to get current view location')
            return

        vl.setOffset(offset)
        view = self._binja_ns.current_ui_view
        view.navigateToViewLocation(vl, False)

    @line_magic
    def navb(self, parameter_s=''):
        try:
            block_index = int(parameter_s)
        except ValueError:
            error(f'invalid arg "{parameter_s}", block index must be integer')
            return

        if block_index < 0:
            error(f'invalid arg "{block_index}", block index must be positive integer')
            return

        fn = self._binja_ns.current_il_function
        if fn is not None:
            self._nav_to_il_block(fn, block_index)
            return

        fn = self._binja_ns.current_function
        if fn is not None:
            self._nav_to_fn_block(fn, block_index)
            return

        error('failed to get current function')
    