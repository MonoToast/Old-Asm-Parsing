from typing import List, Dict, Any, Optional, Union
from instruction import Instruction
import re

amd64_registers_map = [
    # rax group
    "rax", "eax", "ax",
    # rbx group
    "rbx", "ebx", "bx",
    # rcx group
    "rcx", "ecx", "cx",
    # rdx group
    "rdx", "edx", "dx",
    # rsi group
    "rsi", "esi", "si",
    # rdi group
    "rdi", "edi", "di",
    # rbp group
    "rbp", "ebp", "bp",
    # rsp group
    "rsp", "esp", "sp",
    # r8 group
    "r8", "r8d", "r8w",
    # r9 group
    "r9", "r9d", "r9w",
    # r10 group
    "r10", "r10d", "r10w",
    # r11 group
    "r11", "r11d", "r11w",
    # r12 group
    "r12", "r12d", "r12w",
    # r13 group
    "r13", "r13d", "r13w",
    # r14 group
    "r14", "r14d", "r14w",
    # r15 group
    "r15", "r15d", "r15w",
]

reg_mapping = {
    # rax group
    "rax": "rax", "eax": "rax", "ax": "rax",
    # rbx group
    "rbx": "rbx", "ebx": "rbx", "bx": "rbx",
    # rcx group
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx",
    # rdx group
    "rdx": "rdx", "edx": "rdx", "dx": "rdx",
    # rsi group
    "rsi": "rsi", "esi": "rsi", "si": "rsi",
    # rdi group
    "rdi": "rdi", "edi": "rdi", "di": "rdi",
    # rbp group
    "rbp": "rbp", "ebp": "rbp", "bp": "rbp",
    # rsp group
    "rsp": "rsp", "esp": "rsp", "sp": "rsp",
    # r8 group
    "r8": "r8", "r8d": "r8", "r8w": "r8",
    # r9 group
    "r9": "r9", "r9d": "r9", "r9w": "r9",
    # r10 group
    "r10": "r10", "r10d": "r10", "r10w": "r10",
    # r11 group
    "r11": "r11", "r11d": "r11", "r11w": "r11",
    # r12 group
    "r12": "r12", "r12d": "r12", "r12w": "r12",
    # r13 group
    "r13": "r13", "r13d": "r13", "r13w": "r13",
    # r14 group
    "r14": "r14", "r14d": "r14", "r14w": "r14",
    # r15 group
    "r15": "r15", "r15d": "r15", "r15w": "r15",
}

def create_nop() -> Instruction:
    """Utility to create a 'nop' instruction."""
    return Instruction.from_dict({"opcode": "nop"})

def create_instruction(opcode, first, second:Optional[Any] = None):
    if isinstance(first, str) and first.startswith("["): first = parse_mem_data(first)
    if isinstance(second, str) and second.startswith("["): second = parse_mem_data(second)
    if second:
        return Instruction.from_dict({
            "opcode": opcode,
            "operands": [{"type": variable_type(first), "value": first}, {"type": variable_type(second), "value": second}]
        })
    else:
        return Instruction.from_dict({
            "opcode": opcode,
            "operands": [{"type": variable_type(first), "value": first}]
        })
    
def parse_mem_data(address):
    pattern = r'^\[(?P<base>[a-zA-Z_][a-zA-Z0-9_]*)' \
              r'(?:\+(?P<index>[a-zA-Z_][a-zA-Z0-9_]*))?' \
              r'(?:\*(?P<scale>0x[a-fA-F0-9]+))?' \
              r'(?:\+(?P<disp>0x[a-fA-F0-9]+))?\]$'
    
    match = re.fullmatch(pattern, address)
    return {key: match.group(key) or "" for key in ["base", "index", "scale", "disp"]} if match else {}

def variable_type(val: Union[str, Dict[str, Any]]) -> str:
    if isinstance(val, dict):                           return "MEM"
    elif isinstance(val, str) and val.startswith("["):  return "MEM"
    elif isinstance(val, str) and val.removeprefix("-").startswith("0x"): return "IMM"
    elif isinstance(val, str):                          return "REG"
    else:                                               raise ValueError("Could not determine type")

def create_operand(operand: Optional[Union[str, List[str]]]) -> Optional[Dict[str, Any]]:
    r_dict:dict[str, Any] = {}
    if isinstance(operand, list) and len(operand) == 2:
        r_dict["type"], r_dict["value"] = operand
    if isinstance(operand, str):
        r_dict["value"] = parse_mem_data(operand)   if operand.startswith("[") else operand
        r_dict["type"] = ""                         if operand.startswith("?") else variable_type(r_dict["value"])
    return {k: v for k, v in r_dict.items() if v not in (None, "")}

def create_pattern(opcode: Optional[Any] = None, first: Optional[Any] = None, second: Optional[Any] = None) -> Dict[str, Any]:
    pattern: Dict[str, Any] = {}
    if not (opcode or first or second): return {"opcode": "nop"}
    if opcode: pattern["opcode"] = opcode
    pattern["operands"] = []
    pattern["operands"].append(create_operand(first) if first else {})
    if second:pattern["operands"].append(create_operand(second))
    return {k: v for k, v in pattern.items() if v not in (None, "")}

def math_reg(reg, current, op, val):
    bits = register_size(reg)
    match op:
        case "add": r_int = int(current, 16) +  int(val, 16)
        case "sub": r_int = int(current, 16) -  int(val, 16)
        case "xor": r_int = int(current, 16) ^  int(val, 16)
        case "shl": r_int = int(current, 16) << int(val, 16)
        case "shr": r_int = int(current, 16) >> int(val, 16)
        case     _: raise ValueError(f"Unsupported operation: {op}")

    return format(r_int & ((1 << bits) - 1), f'0{(bits // 4)}X')

def register_size(reg: str) -> int:
    if not reg in amd64_registers_map: raise ValueError("Invalid register")
    if reg.startswith("r") and reg[1].isdigit():
        match reg[-1]:
            case 'w': return 16
            case 'd': return 32
            case _:   return 64 
    elif not reg[1].isdigit():
        match reg[0]:
            case 'r': return 64
            case 'e': return 32
            case _:   return 16
    raise ValueError("Invalid register")