import json
from typing import Dict, Any, Optional

class Memory:
    def __init__(self, mem: Optional[Any] = None, insn: Optional[Any] = None):
        if mem and insn:
            # Use the capstone API to extract register names
            self.base  = insn.reg_name(mem.base) if mem.base > 0 else ""
            self.index = insn.reg_name(mem.index) if mem.index > 0 else ""
            self.scale = hex(mem.scale) if mem.scale > 1 else ""
            self.disp  = hex(mem.disp) if mem.disp > 0 else ""
        else:
            self.base = self.index = self.scale = self.disp = ""

    def __str__(self) -> str:
        idx = f"{self.index}*{self.scale}" if self.scale else self.index
        return f"qword [{'+'.join(filter(None, [self.base, idx, self.disp]))}]"
    
    def to_dict(self) -> Dict[str, str]:
        return {"base": self.base, "index": self.index, "scale": self.scale, "disp": self.disp}
    
    @classmethod
    def from_dict(cls, d: Dict[str, str]) -> 'Memory':
        mem = cls()
        mem.base  = d.get("base", "")
        mem.index = d.get("index", "")
        mem.scale = d.get("scale", "")
        mem.disp  = d.get("disp", "")
        return mem

class Operand:
    def __init__(self, operand: Optional[Any] = None, insn: Optional[Any] = None):
        if operand and insn:
            match operand.type:
                case 1: self.value, self.type = insn.reg_name(operand.reg), "REG"
                case 2: self.value, self.type = hex(operand.imm)          , "IMM"
                case 3: self.value, self.type = Memory(operand.mem, insn) , "MEM"
        else:
            self.type, self.value = "INVALID", None

    def __str__(self) -> str:
        return str(self.value)
    
    def to_dict(self) -> Dict[str, Any]:
        # For memory operands, use the Memory.to_dict() conversion.
        return {
            "type": self.type,
            "value": self.value.to_dict() if hasattr(self.value, "to_dict") else self.value #type: ignore
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Operand':
        op = cls()
        op.type = d.get("type", "INVALID")
        op.value = Memory.from_dict(d.get("value", {})) if op.type == "MEM" else d.get("value")
        return op

class Instruction:
    def __init__(self, insn: Optional[Any] = None):
        if insn:
            # Normalize the opcode (e.g. replace movabs with mov)
            self.opcode = insn.mnemonic.replace("movabs", "mov")
            self.operands = [Operand(op, insn) for op in insn.operands]
        else:
            self.opcode, self.operands = "", []

    def __str__(self) -> str:
        return f"{self.opcode} {', '.join(map(str, self.operands))}" if self.operands else self.opcode

    def to_dict(self) -> Dict[str, Any]:
        return {"opcode": self.opcode, "operands": [op.to_dict() for op in self.operands]}
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Instruction':
        inst = cls()
        inst.opcode = d.get("opcode", "")
        inst.operands = [Operand.from_dict(op) for op in d.get("operands", [])]
        return inst

    @classmethod
    def from_json(cls, json_str: str) -> 'Instruction':
        return cls.from_dict(json.loads(json_str))