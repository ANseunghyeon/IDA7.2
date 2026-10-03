# -*- coding: utf-8 -*-
"""IDA 7.2 / Python 2.7: locate typed structure field accesses in pseudocode.

File > Script file, then use find_struct_field("MY_STRUCT", "field").
Lines are 1-based indexes into cfunc.get_pseudocode(), including declarations.
"""
from __future__ import print_function

import time
import idaapi
import ida_hexrays as hx
import ida_kernwin
import ida_lines
import ida_typeinf as ti
import idautils
import idc


def _char(value):
    return chr(value) if isinstance(value, int) else value


def _line_index(lines):
    """One pass over encoded pseudocode: ctree item index -> line numbers."""
    marker = _char(ida_lines.COLOR_ON) + _char(ida_lines.COLOR_ADDR)
    width = ida_lines.COLOR_ADDR_SIZE
    result = {}
    for y, line in enumerate(lines):
        raw = line.line
        pos = 0
        while True:
            pos = raw.find(marker, pos)
            if pos < 0:
                break
            start = pos + len(marker)
            encoded = raw[start:start + width]
            pos = start + width
            try:
                anchor = hx.ctree_anchor_t()
                anchor.value = int(encoded, 16)
            except ValueError:
                continue
            if anchor.is_citem_anchor():
                result.setdefault(anchor.get_index(), set()).add(y + 1)
    return result


def _coordinates(cfunc, expr):
    """Fallback for an item without a direct printed anchor."""
    try:
        xy = cfunc.find_item_coords(expr)
        if isinstance(xy, tuple) and len(xy) == 2:
            return [int(xy[1]) + 1] if xy[1] >= 0 else []
    except TypeError:
        pass
    # Some older SWIG bindings expose the C++ output-pointer signature.
    pointer = getattr(idaapi, "int_pointer", None)
    if pointer is not None:
        x, y = pointer(), pointer()
        if cfunc.find_item_coords(expr, x, y):
            return [y.value() + 1] if y.value() >= 0 else []
    return []


class _FieldVisitor(hx.ctree_visitor_t):
    def __init__(self, target, member_keys):
        hx.ctree_visitor_t.__init__(self, hx.CV_FAST)
        self.target = target
        self.member_keys = member_keys
        self.matches = []
        self.type_cache = {}

    def visit_expr(self, expr):
        if expr.op not in (hx.cot_memref, hx.cot_memptr):
            return 0
        if int(expr.m) not in self.member_keys:
            return 0
        base = expr.x.type
        if expr.op == hx.cot_memptr:
            if not base.is_ptr():
                return 0
            base = base.get_pointed_object()
        if not base.is_udt():
            return 0
        # Serialized type identity includes named type references; cache only
        # within this function so that later IDB type edits cannot leave it stale.
        key = base.serialize()
        if key not in self.type_cache:
            normalized = ti.tinfo_t(base)
            normalized.clr_const()
            normalized.clr_volatile()
            self.type_cache[key] = normalized.equals_to(self.target)
        if self.type_cache[key]:
            self.matches.append((expr, self.member_keys[int(expr.m)]))
        return 0


def find_struct_field(struct_name, field_name=None, function_eas=None):
    """Return list of dictionaries; field_name=None searches all direct fields.

    function_eas=None scans all functions (complete for visible typed accesses).
    An explicit iterable scans only those functions; it may omit other uses.
    Reads, writes and address-taking are all included, without classification.
    """
    if not hx.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is not available")
    target = ti.tinfo_t()
    if not target.get_named_type(ti.get_idati(), struct_name):
        raise ValueError("Unknown local type: " + struct_name)
    if not target.is_udt():
        raise ValueError("Not a structure/union: " + struct_name)
    target.clr_const()
    target.clr_volatile()
    udt = ti.udt_type_data_t()
    if not target.get_udt_details(udt):
        raise ValueError("Cannot read members: " + struct_name)
    keys = {}
    for index, member in enumerate(udt):
        if field_name is not None and member.name != field_name:
            continue
        if member.type.is_bitfield() or (not target.is_union() and int(member.offset) % 8):
            raise ValueError("Bitfields are not supported")
        key = index if target.is_union() else int(member.offset) // 8
        if key in keys:
            raise ValueError("Overlapping member offsets are not supported")
        keys[key] = member.name
    if not keys:
        raise ValueError("No matching direct member: " + str(field_name))

    rows, failures = [], []
    started = time.time()
    count = 0
    cancelled = False
    ida_kernwin.show_wait_box("Finding structure field accesses...")
    # Use a cancellable box; no background worker touches IDA's database.
    ida_kernwin.replace_wait_box("Finding structure field accesses...")
    try:
        eas = idautils.Functions() if function_eas is None else function_eas
        seen = set()
        for ea in eas:
            func = idaapi.get_func(ea)
            if func is None or func.start_ea in seen:
                continue
            ea = func.start_ea
            seen.add(ea)
            if ida_kernwin.user_cancelled():
                cancelled = True
                break
            count += 1
            if count % 20 == 1:
                ida_kernwin.replace_wait_box("Scanned %d functions; now 0x%X" % (count, ea))
            try:
                cfunc = hx.decompile(ea)
            except hx.DecompilationFailure as error:
                failures.append((ea, str(error)))
                continue
            if cfunc is None:
                failures.append((ea, "No pseudocode"))
                continue
            visitor = _FieldVisitor(target, keys)
            visitor.apply_to(cfunc.body, None)
            if not visitor.matches:
                continue
            # Render matching functions only; rendering assigns item indexes.
            lines = cfunc.get_pseudocode()
            mapping = _line_index(lines)
            dedup = set()
            for expr, member_name in visitor.matches:
                numbers = sorted(mapping.get(expr.index, ()))
                if not numbers:
                    numbers = _coordinates(cfunc, expr)
                # Preserve unmappable accesses instead of silently dropping them.
                for number in numbers or [None]:
                    identity = (number, member_name, int(expr.ea))
                    if identity in dedup:
                        continue
                    dedup.add(identity)
                    row = dict(function_ea=ea, function=idc.get_func_name(ea),
                               field=member_name, line=number, access_ea=int(expr.ea),
                               text=ida_lines.tag_remove(lines[number - 1].line)
                               if number is not None else "<unmapped ctree item>")
                    rows.append(row)
                    print("0x%X %s : %s  %s.%s  %s" %
                          (ea, row["function"], number if number is not None else "?",
                           struct_name, member_name, row["text"].strip()))
    finally:
        ida_kernwin.hide_wait_box()
    for ea, error in failures:
        print("[decompile failed] 0x%X: %s" % (ea, error))
    print("%d hits; %d functions; %d failed; %.2fs; %s" %
          (len(rows), count, len(failures), time.time() - started,
           "PARTIAL (cancelled)" if cancelled else "finished"))
    return rows


if __name__ == "__main__":
    name = ida_kernwin.ask_str("", 0, "Structure type name")
    if name:
        field = ida_kernwin.ask_str("", 0, "Direct field name (empty = all fields)")
        if field is not None:
            FIELD_RESULTS = find_struct_field(name, field or None)
