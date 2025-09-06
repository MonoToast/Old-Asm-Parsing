import copy
from typing import List, Dict, Any, Tuple, Callable, Optional
from instruction import Instruction
from dsl_helpers import *

class Rule:
    def __init__(self, name: str, pattern: List[Dict[str, Any]],
                 replace_func: Callable[[Dict[str, Any]], List[Instruction]]):
        self.name = name
        self.pattern = pattern
        self.replace_func = replace_func

def is_placeholder(item: Any) -> bool:
    return isinstance(item, str) and item.startswith('?')

def bind(var: str, value: Any, bindings: Dict[str, Any]) -> bool:
    if var in bindings:
        return str(reg_size_ambulation(bindings[var])) == str(reg_size_ambulation(value))
    bindings[var] = value
    return True

def reg_size_ambulation(reg):
    if not isinstance(reg, str): return reg
    return reg_mapping.get(reg, reg)

def match_literal(pattern: Any, value: Any, bindings: Dict[str, Any]) -> bool:
    if is_placeholder(pattern):
        return bind(pattern[1:], value, bindings)
    if isinstance(pattern, list):
        for alt in pattern:
            new_bindings = copy.deepcopy(bindings)
            if match_literal(alt, value, new_bindings):
                bindings.clear()
                bindings.update(new_bindings)
                return True
        return False
    return str(reg_size_ambulation(pattern)) == str(reg_size_ambulation(value))

def match_dict(pattern: Dict[str, Any], actual: Dict[str, Any], bindings: Dict[str, Any]) -> bool:
    return all(
        key in actual and (
            match_dict(pat_val, actual[key], bindings) if isinstance(pat_val, dict)
            else match_literal(pat_val, actual[key], bindings)
        )
        for key, pat_val in pattern.items()
    )

def match_operand(pattern_operand: Any, operand: Any, bindings: Dict[str, Any]) -> bool:
    if not isinstance(operand, dict) and hasattr(operand, "to_dict"):
        operand = operand.to_dict()
    if is_placeholder(pattern_operand):
        return bind(pattern_operand[1:], operand, bindings)
    return match_dict(pattern_operand, operand, bindings) if isinstance(pattern_operand, dict) \
           else match_literal(pattern_operand, operand, bindings)

def match_instruction(pattern: Dict[str, Any], instr: Instruction, bindings: Dict[str, Any]) -> bool:
    pat_opcode = pattern.get("opcode", "")
    if isinstance(pat_opcode, list):
        if str(instr.opcode) in {str(op) for op in pat_opcode}:
            bind("opcode", instr.opcode, bindings)
        else:
            return False
    elif not match_literal(pat_opcode, instr.opcode, bindings):
        return False
    pat_operands = pattern.get("operands", [])
    if len(pat_operands) != len(instr.operands):
        return False
    return all(match_operand(pat_op, op, bindings)
               for pat_op, op in zip(pat_operands, instr.operands))

def match_rule(rule: Rule, instructions: List[Instruction], index: int) -> Optional[Tuple[int, Dict[str, Any]]]:
    bindings = {}
    if index + len(rule.pattern) > len(instructions):
        return None
    for i, pat in enumerate(rule.pattern):
        if not match_instruction(pat, instructions[index + i], bindings):
            return None
    return len(rule.pattern), bindings

def apply_rules(instructions: List[Instruction], rules: List[Rule]) -> List[Instruction]:
    result = []
    i = 0
    while i < len(instructions):
        for rule in rules:
            res = match_rule(rule, instructions, i)
            if res:
                count, bindings = res
                new_instrs = rule.replace_func(bindings)
                log_replacement(rule.name, instructions[i:i+count], new_instrs)
                i += count
                if new_instrs[0].opcode == "nop": break
                result.extend(new_instrs)
                break
        else:
            result.append(instructions[i])
            i += 1
    return result

def log_replacement(label: str, removed: List[Instruction], added: List[Instruction]):
    print(f"Rule '{label}' applied:\nRemoved:")
    for r in removed:
        print(f"    {r}")
    print("Added:")
    for a in added:
        print(f"    {a}")