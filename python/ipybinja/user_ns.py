import logging
import threading
import weakref

from typing import Optional, Union, Mapping
from weakref import WeakValueDictionary, WeakKeyDictionary, proxy

import binaryninja as bn
import binaryninjaui as bnui

from wrapt import ObjectProxy


ILBasicBlockTypes = Union[bn.LowLevelILBasicBlock, bn.MediumLevelILBasicBlock, bn.HighLevelILBasicBlock]
ILInstructionTypes = Union[bn.LowLevelILInstruction, bn.MediumLevelILInstruction, bn.HighLevelILInstruction]


class BinjaContextVarSnapshot:

    current_ui_context: Optional[bnui.UIContext]
    current_ui_view_frame: Optional[bnui.ViewFrame]
    current_ui_view: Optional[bnui.View]
    current_ui_action_handler: Optional[bnui.UIActionHandler]
    current_ui_view_location: Optional[bnui.ViewLocation]
    current_ui_action_context: Optional[bnui.UIActionContext]
    current_token: Optional[bn.InstructionTextToken]
    current_function: Optional[bn.Function]
    current_variable: Optional[bn.Variable]
    current_il_function: Optional[Union[bn.Function, bn.ILFunctionType]]
    current_il_index: Optional[int]
    current_il_basic_block: Optional[ILBasicBlockTypes]
    current_il_instruction: Optional[ILInstructionTypes]
    current_view: Optional[bn.BinaryView]
    bv: Optional[bn.BinaryView]
    current_address: int
    here: int
    current_comment: Optional[str]
    current_sections: list[bn.Section]
    current_segment: Optional[bn.Segment]
    current_symbols: list[bn.CoreSymbol]
    current_symbol: Optional[bn.CoreSymbol]
    current_data_var: Optional[bn.DataVariable]
    current_hlil: Optional[bn.HighLevelILFunction]
    current_mlil: Optional[bn.MediumLevelILFunction]
    current_llil: Optional[bn.LowLevelILFunction]
    current_raw_offset: int
    current_selection: Optional[tuple[int, int]]
    current_basic_block: Optional[bn.BasicBlock]
    current_thread: threading.Thread

    def __init__(self, ctx: Optional[bnui.UIContext]):
        self.current_ui_context = ctx
        self.current_ui_view_frame = ctx.getCurrentViewFrame() if ctx else None
        self.current_ui_view = ctx.getCurrentView() if ctx else None
        self.current_ui_action_handler = ctx.getCurrentActionHandler() if ctx else None
        view_frame = self.current_ui_view_frame
        view = self.current_ui_view
        self.current_ui_view_location = view_frame.getViewLocation() if view_frame else None
        self.current_ui_action_context = view.actionContext() if view else None
        action_ctx = self.current_ui_action_context
        token_state = action_ctx.token if action_ctx else None
        self.current_token = token_state.token if token_state and token_state.valid else None
        view_location = self.current_ui_view_location
        self.current_function = view_location.getFunction() if view_location else None
        func = self.current_function
        self.current_variable = bn.Variable.from_core_variable(func, token_state.localVar) \
            if func and token_state and token_state.localVarValid else None
        self.current_il_function = self._get_il_function(func, view_location)
        il_func = self.current_il_function
        self.current_il_index = view_location.getInstrIndex() if view_location else None
        il_index = self.current_il_index
        self.current_il_basic_block = il_func.get_basic_block_at(il_index) if il_func and il_index else None
        self.current_il_instruction = il_func[il_index] \
            if il_func and il_index and il_index < len(il_func) is not None else None
        self.current_view = view_frame.getCurrentBinaryView() if view_frame else None
        bv = self.current_view
        self.bv = bv
        self.current_address = view_location.getOffset() if view_location else 0
        self.here = self.current_address
        address = self.current_address if view_location and view_location.isValid() else None
        self.current_comment = bv.get_comment_at(address) if bv and address is not None else None
        self.current_sections = bv.get_sections_at(address) if bv and address is not None else []
        self.current_segment = bv.get_segment_at(address) if bv and address is not None else None
        self.current_symbols = bv.get_symbols(address, 1) if bv and address is not None else []
        self.current_symbol = bv.get_symbol_at(address) if bv and address is not None else None
        self.current_data_var = bv.get_data_var_at(address) if bv and address is not None else None
        self.current_hlil = self._read_il(func, 'HLIL')
        self.current_mlil = self._read_il(func, 'MLIL')
        self.current_llil = self._read_il(func, 'LLIL')
        self.current_raw_offset = bv.get_data_offset_for_address(address) if bv and address is not None else 0
        self.current_selection = view_frame.getSelectionOffsets() if view_frame else None
        self.current_basic_block = func.get_basic_block_at(address) if func and address is not None else None
        self.current_thread = threading.current_thread()
    
    def _read_il(self, fn: bn.Function | None, variant: str):
        if fn is None:
            return None
        try:
            match variant:
                case 'LLIL':
                    return fn.llil
                case 'MLIL':
                    return fn.mlil
                case 'HLIL':
                    return fn.hlil
                case _:
                    raise Exception('todo')
        except bn.ILException:
            return None

    @classmethod
    def _get_il_function(cls, function: Optional[bn.Function], view_location: Optional[bnui.ViewLocation]) \
            -> Optional[Union[bn.Function, bn.ILFunctionType]]:
        from binaryninja import FunctionGraphType as GraphType
        if function is None or view_location is None or not view_location.isValid():
            return None
        il_type = view_location.getILViewType()
        if il_type == GraphType.NormalFunctionGraph:
            return None
        elif il_type == GraphType.LowLevelILFunctionGraph:
            return function.llil
        elif il_type == GraphType.LiftedILFunctionGraph:
            return function.lifted_il
        elif il_type == GraphType.LowLevelILSSAFormFunctionGraph:
            return function.llil.ssa_form if function.llil is not None else None
        elif il_type == GraphType.MediumLevelILFunctionGraph:
            return function.mlil
        elif il_type == GraphType.MediumLevelILSSAFormFunctionGraph:
            return function.mlil.ssa_form if function.mlil is not None else None
        elif il_type == GraphType.MappedMediumLevelILFunctionGraph:
            return function.mapped_medium_level_il
        elif il_type == GraphType.MappedMediumLevelILSSAFormFunctionGraph:
            return function.mapped_medium_level_il.ssa_form if function.mapped_medium_level_il is not None else None
        elif il_type == GraphType.HighLevelILFunctionGraph:
            return function.hlil
        elif il_type == GraphType.HighLevelILSSAFormFunctionGraph:
            return function.hlil.ssa_form if function.hlil is not None else None
        elif il_type == GraphType.HighLevelLanguageRepresentationFunctionGraph:
            return None
        raise Exception(f'unexpected il type {il_type}')


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class ContextVarSnapshotManager(metaclass=Singleton):

    _cache: WeakKeyDictionary

    def __init__(self):
        self._cache = WeakKeyDictionary()
    
    def update_cache(self):
        contexts = set(bnui.UIContext.allContexts())
        for k in list(self._cache.keys()):
            if k not in contexts:
                del self._cache[k]
        for ctx in contexts:
            snapshot = BinjaContextVarSnapshot(ctx)
            if ctx in self._cache:
                self._cache[ctx].__wrapped__ = snapshot
            else:
                self._cache[ctx] = ObjectProxy(snapshot)

    def get_snapshot(self, ctx: bnui.UIContext) -> BinjaContextVarSnapshot:
        return proxy(self._cache[ctx])


class UserNamespaceProvider(dict):

    _MAGIC_VARS = set(vars(BinjaContextVarSnapshot(None)).keys())

    def __init__(self, mapping=(), **kwargs):
        super().__init__(mapping, **kwargs)
        # Reserve keys for magic variables
        for var in self._MAGIC_VARS:
            super().__setitem__(var, None)
        self._session_context_overrides = WeakValueDictionary()
        self._magic_vars = BinjaContextVarSnapshot(None)
            
    def update_magic_snapshot(self, remote_client_id: Optional[str]) -> None:
        if remote_client_id:
            context = None
        else:
            context = bnui.UIContext.activeContext()

        ContextVarSnapshotManager().update_cache()
        self._magic_vars = ContextVarSnapshotManager().get_snapshot(context) if context else \
            BinjaContextVarSnapshot(None)

    def __getitem__(self, k):
        if k in self._MAGIC_VARS:
            return self._get_magic_var(k)
        return super().__getitem__(k)

    def __setitem__(self, k, v):
        self._check_mutate(k)
        return super().__setitem__(k, v)

    def __delitem__(self, k):
        self._check_mutate(k)
        return super().__delitem__(k)

    def get(self, k, default=None):
        if k in self._MAGIC_VARS:
            return self._get_magic_var(k)
        return super().get(k, default)

    def setdefault(self, k, default=None):
        self._check_mutate(k)
        return super().setdefault(k, default)

    def pop(self, k, v=object()):
        self._check_mutate(k)
        return super().pop(k, v)

    def _get_magic_var(self, k):
        return getattr(self._magic_vars, k)

    @classmethod
    def _check_mutate(cls, k):
        if k in cls._MAGIC_VARS:
            raise Exception(f'cannot mutate magic variable {k}')

    @classmethod
    def _check_update(cls, k, v):
        if k in cls._MAGIC_VARS and v is not None:
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
