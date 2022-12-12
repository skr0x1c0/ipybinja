import threading
from typing import Optional, Union, Mapping

import binaryninja as bn
import binaryninjaui as bnui


def _with_ref(v, parent):
    # Keep a reference of parent c++ object in v
    # This prevents parent from being destroyed
    # while v is still alive
    if v is not None:
        v._self_ref = parent
    return v


class _BinjaMagicVariablesProvider:
    MAGIC_VARIABLES = {
        'current_thread',
        'current_view',
        'bv',
        'current_function',
        'current_basic_block',
        'current_address',
        'here',
        'current_selection',
        'current_raw_offset',
        'current_llil',
        'current_mlil',
        'current_hlil',
        'current_data_var',
        'current_symbol',
        'current_symbols',
        'current_segment',
        'current_sections',
        'current_comment',
        'current_il_index',
        'current_il_function',
        'current_il_instruction',
        'current_il_basic_block',
        'current_ui_context',
        'current_ui_view_frame',
        'current_ui_view',
        'current_ui_action_handler',
        'current_ui_view_location',
        'current_ui_action_context',
        'current_token',
        'current_variable'
    }

    @property
    def current_thread(self) -> threading.Thread:
        return threading.current_thread()

    @property
    def current_view(self) -> Optional[bn.BinaryView]:
        frame = self.current_ui_view_frame
        if frame is None:
            return None
        return _with_ref(frame.getCurrentBinaryView(), frame)

    @property
    def bv(self) -> Optional[bn.BinaryView]:
        return self.current_view

    @property
    def current_function(self) -> Optional[bn.Function]:
        view_location = self.current_ui_view_location
        if view_location is None or not view_location.isValid():
            return None
        return view_location.getFunction()

    @property
    def current_basic_block(self) -> Optional[bn.BasicBlock]:
        function = self.current_function
        location = self.current_address
        if function is None:
            return None
        return function.get_basic_block_at(location)

    @property
    def current_address(self) -> int:
        vl = self.current_ui_view_location
        if vl is None:
            return 0
        return vl.getOffset()

    @property
    def here(self) -> int:
        return self.current_address

    @property
    def current_selection(self) -> Optional[tuple[int, int]]:
        frame = self.current_ui_view_frame
        if frame is None:
            return None
        selection = frame.getSelectionOffsets()
        return selection

    @property
    def current_raw_offset(self) -> int:
        bv = self.bv
        if not bv:
            return 0
        return bv.get_data_offset_for_address(self.current_address)

    @property
    def current_llil(self) -> Optional[bn.LowLevelILFunction]:
        function = self.current_function
        if function is None:
            return None
        return function.llil

    @property
    def current_mlil(self) -> Optional[bn.MediumLevelILFunction]:
        function = self.current_function
        if function is None:
            return None
        return function.mlil

    @property
    def current_hlil(self) -> Optional[bn.HighLevelILFunction]:
        function = self.current_function
        if function is None:
            return None
        return function.hlil

    @property
    def current_data_var(self) -> Optional[bn.DataVariable]:
        bv = self.bv
        if bv is None:
            return None
        return bv.get_data_var_at(self.current_address)

    @property
    def current_symbol(self) -> Optional[bn.CoreSymbol]:
        bv = self.bv
        if bv is None:
            return None
        return bv.get_symbol_at(self.current_address)

    @property
    def current_symbols(self) -> list[bn.CoreSymbol]:
        bv = self.bv
        if bv is None:
            return []
        return bv.get_symbols(self.current_address, 1)

    @property
    def current_segment(self) -> Optional[bn.Segment]:
        bv = self.bv
        if bv is None:
            return None
        return bv.get_segment_at(self.current_address)

    @property
    def current_sections(self) -> list[bn.Section]:
        bv = self.bv
        if bv is None:
            return []
        return bv.get_sections_at(self.current_address)

    @property
    def current_comment(self) -> Optional[str]:
        bv = self.bv
        if bv is None:
            return None
        return bv.get_comment_at(self.current_address)

    @property
    def current_il_index(self) -> Optional[int]:
        view_location = self.current_ui_view_location
        if view_location is None or not view_location.isValid():
            return None
        return view_location.getInstrIndex()

    @property
    def current_il_function(self) -> Optional[Union[bn.Function, bn.ILFunctionType]]:
        function = self.current_function
        view_location = self.current_ui_view_location
        if function is None or view_location is None or not view_location.isValid():
            return None
        il_type = view_location.getILViewType()
        cls = bn.FunctionGraphType
        if il_type == cls.NormalFunctionGraph:
            return None
        elif il_type == cls.LowLevelILFunctionGraph:
            return function.llil
        elif il_type == cls.LiftedILFunctionGraph:
            return function.lifted_il
        elif il_type == cls.LowLevelILSSAFormFunctionGraph:
            return function.llil.ssa_form
        elif il_type == cls.MediumLevelILFunctionGraph:
            return function.mlil
        elif il_type == cls.MediumLevelILSSAFormFunctionGraph:
            return function.mlil.ssa_form
        elif il_type == cls.MappedMediumLevelILFunctionGraph:
            return function.mapped_medium_level_il
        elif il_type == cls.MappedMediumLevelILSSAFormFunctionGraph:
            return function.mapped_medium_level_il.ssa_form
        elif il_type == cls.HighLevelILFunctionGraph:
            return function.hlil
        elif il_type == cls.HighLevelILSSAFormFunctionGraph:
            return function.hlil.ssa_form
        elif il_type == cls.HighLevelLanguageRepresentationFunctionGraph:
            return None
        raise Exception(f'unexpected il type {il_type}')

    @property
    def current_il_instruction(self) -> Optional:
        function = self.current_il_function
        instr_index = self.current_il_index
        if function is None or instr_index is None:
            return None
        if instr_index > len(function):
            return None
        return function[instr_index]

    @property
    def current_il_basic_block(self) -> Optional:
        function = self.current_il_function
        instr_index = self.current_il_index
        if function is None or instr_index is None:
            return None
        return function.get_basic_block_at(instr_index)

    @property
    def current_ui_context(self) -> Optional[bnui.UIContext]:
        return bnui.UIContext.activeContext()

    @property
    def current_ui_view_frame(self) -> Optional[bnui.ViewFrame]:
        ctx = self.current_ui_context
        if ctx is None:
            return None
        return _with_ref(ctx.getCurrentViewFrame(), ctx)

    @property
    def current_ui_view(self) -> Optional[bnui.View]:
        ctx = self.current_ui_context
        if ctx is None:
            return None
        return _with_ref(ctx.getCurrentView(), ctx)

    @property
    def current_ui_action_handler(self) -> Optional[bnui.UIActionHandler]:
        ctx = self.current_ui_context
        if ctx is None:
            return None
        return _with_ref(ctx.getCurrentActionHandler(), ctx)

    @property
    def current_ui_view_location(self) -> Optional[bnui.ViewLocation]:
        view_frame = self.current_ui_view_frame
        if view_frame is None:
            return None
        return _with_ref(view_frame.getViewLocation(), view_frame)

    @property
    def current_ui_action_context(self):
        view = self.current_ui_view
        if view is not None:
            return _with_ref(view.actionContext(), view)
        ctx = self.current_ui_context
        if ctx is None:
            return None
        return _with_ref(ctx.getCurrentActionHandler(), ctx)

    @property
    def current_token(self) -> Optional[bn.InstructionTextToken]:
        action_ctx = self.current_ui_action_context
        if action_ctx is None or not hasattr(action_ctx, 'token'):
            return None
        token_state = action_ctx.token
        if not token_state.valid:
            return None
        return token_state.token

    @property
    def current_variable(self) -> Optional[bn.Variable]:
        action_ctx = self.current_ui_action_context
        if action_ctx is None or not hasattr(action_ctx, 'token'):
            return None
        token_state = action_ctx.token
        if not token_state.localVarValid:
            return None
        func = self.current_function
        if func is None:
            return None
        return bn.Variable.from_core_variable(func, token_state.localVar)
    
    def take_snapshot(self) -> dict:
        return {k: getattr(self, k) for k in self.MAGIC_VARIABLES}


class UserNamespaceProvider(dict):
    def __init__(self, mapping=(), **kwargs):
        super().__init__(mapping, **kwargs)
        self._magic_var_provider = _BinjaMagicVariablesProvider()
        # Reserve keys for magic variables
        for var in _BinjaMagicVariablesProvider.MAGIC_VARIABLES:
            super().__setitem__(var, None)
        self.update_magic_snapshot()
            
    def update_magic_snapshot(self) -> None:
        self._magic_vars = self._magic_var_provider.take_snapshot()

    def __getitem__(self, k):
        if k in _BinjaMagicVariablesProvider.MAGIC_VARIABLES:
            return self._get_magic_var(k)
        return super().__getitem__(k)

    def __setitem__(self, k, v):
        self._check_mutate(k)
        return super().__setitem__(k, v)

    def __delitem__(self, k):
        self._check_mutate(k)
        return super().__delitem__(k)

    def get(self, k, default=None):
        if k in _BinjaMagicVariablesProvider.MAGIC_VARIABLES:
            return self._get_magic_var(k)
        return super().get(k, default)

    def setdefault(self, k, default=None):
        self._check_mutate(k)
        return super().setdefault(k, default)

    def pop(self, k, v=object()):
        self._check_mutate(k)
        return super().pop(k, v)

    def _get_magic_var(self, k):
        return self._magic_vars[k]

    @classmethod
    def _check_mutate(cls, k):
        if k in _BinjaMagicVariablesProvider.MAGIC_VARIABLES:
            raise Exception(f'cannot mutate magic variable {k}')

    @classmethod
    def _check_update(cls, k, v):
        if k in _BinjaMagicVariablesProvider.MAGIC_VARIABLES and v is not None:
            raise Exception(f'cannot update magic variable {k} to {v}')

    def update(self, m: Mapping, **kwargs) -> None:
        for k, v in m.items():
            self._check_update(k, v)
        for k, v in kwargs:
            self._check_update(k, v)
        return super().update(m, **kwargs)

    def copy(self):
        return type(self)(self)

    def __iter__(self):
        raise Exception('todo')
