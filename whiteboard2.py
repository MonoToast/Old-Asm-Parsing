from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple, Union, Mapping
from types import MappingProxyType
from capstone import CS_ARCH_X86, CS_MODE_64, CsInsn, x86_const, Cs
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86Op

SIZE_PREFIX = {1: "byte", 2: "word", 4: "dword", 8: "qword"}

_CS = Cs(CS_ARCH_X86, CS_MODE_64)

# -----------------------------------------------------------------------------
# region ASM Data Classes

class Register(Enum):

    NONE = (0, "none", 0)
    RAX, EAX, AX, AH, AL =  ((8, "rax", 0), (4, "rax", 0), (2, "rax", 0), (1, "rax", 1), (1, "rax", 0))
    RBX, EBX, BX, BH, BL =  ((8, "rbx", 0), (4, "rbx", 0), (2, "rbx", 0), (1, "rbx", 1), (1, "rbx", 0))
    RCX, ECX, CX, CH, CL =  ((8, "rcx", 0), (4, "rcx", 0), (2, "rcx", 0), (1, "rcx", 1), (1, "rcx", 0))
    RDX, EDX, DX, DH, DL =  ((8, "rdx", 0), (4, "rdx", 0), (2, "rdx", 0), (1, "rdx", 1), (1, "rdx", 0))
    RSI, ESI, SI, SIL =     ((8, "rsi", 0), (4, "rsi", 0), (2, "rsi", 0), (1, "rsi", 0))
    RDI, EDI, DI, DIL =     ((8, "rdi", 0), (4, "rdi", 0), (2, "rdi", 0), (1, "rdi", 0))
    RSP, ESP, SP, SPL =     ((8, "rsp", 0), (4, "rsp", 0), (2, "rsp", 0), (1, "rsp", 0))
    R8, R8D, R8W, R8B =     ((8, "r8",  0), (4, "r8",  0), (2, "r8",  0), (1, "r8",  0))
    R9, R9D, R9W, R9B =     ((8, "r9",  0), (4, "r9",  0), (2, "r9",  0), (1, "r9",  0))
    R10, R10D, R10W, R10B = ((8, "r10", 0), (4, "r10", 0), (2, "r10", 0), (1, "r10", 0))
    R11, R11D, R11W, R11B = ((8, "r11", 0), (4, "r11", 0), (2, "r11", 0), (1, "r11", 0))
    R12, R12D, R12W, R12B = ((8, "r12", 0), (4, "r12", 0), (2, "r12", 0), (1, "r12", 0))
    R13, R13D, R13W, R13B = ((8, "r13", 0), (4, "r13", 0), (2, "r13", 0), (1, "r13", 0))
    R14, R14D, R14W, R14B = ((8, "r14", 0), (4, "r14", 0), (2, "r14", 0), (1, "r14", 0))
    R15, R15D, R15W, R15B = ((8, "r15", 0), (4, "r15", 0), (2, "r15", 0), (1, "r15", 0))

    @property
    def concrete(self) -> str:
        return self.name.lower()

    @property
    def size(self) -> int:
        return self.value[0]

    @property
    def canonical(self) -> str:
        return self.value[1]

    @property
    def offset(self) -> int:
        return self.value[2]
    
    def __str__(self) -> str:
        return self.concrete

@dataclass(frozen=True)
class Immediate:
    value: int

    def __str__(self) -> str:
        return f"{self.value:#x}"

@dataclass(frozen=True)
class Memory:
    size: int
    base: Register = Register.NONE
    index: Register = Register.NONE
    scale: int = 1
    disp: int = 0

    def __str__(self) -> str:
        parts = []
        if self.base != Register.NONE:
            parts.append(str(self.base))
        if self.index != Register.NONE:
            parts.append(f"{self.index}*{self.scale}" if self.scale != 1 else str(self.index))
        if self.disp != 0:
            parts.append(f"{self.disp:#x}")
        return f"{SIZE_PREFIX.get(self.size, '')} [{' + '.join(parts)}]"

Operand = Union[Register, Immediate, Memory]

@dataclass(frozen=True)
class Instruction:
    opcode: str = field(default="nop")
    operands: Tuple[Operand, ...] = field(default_factory=tuple)

    def __str__(self) -> str:
        return f"{self.opcode} {', '.join([str(op) for op in self.operands])}"

@dataclass(frozen=True)
class BasicBlock:
    name: str
    lines: Tuple[Instruction, ...] = field(default_factory=tuple)
    successors: Tuple["BasicBlock", ...] = field(default_factory=tuple)
    predecessors: Tuple["BasicBlock", ...] = field(default_factory=tuple)

    def __str__(self) -> str:
        return "\n".join([f"\t{self.name}:"] + [f"\t\t{str(i)}" for i in self.lines])

@dataclass(frozen=True)
class Function:
    name: str
    blocks: Tuple[BasicBlock, ...] = field(default_factory=tuple)

    def __str__(self) -> str:
        return "\n".join([f"{self.name}"] + [f"\t{str(b)}" for b in self.blocks])

# endregion
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# region SSA Data Classes


@dataclass(frozen=True)
class PhiInstruction:
    target: Register
    sources: Mapping[BasicBlock, Operand] = field(default_factory=lambda: MappingProxyType({}))
    
    def __post_init__(self):
        object.__setattr__(self, 'sources', MappingProxyType(dict(self.sources)))

@dataclass(frozen=True)
class SSARegister:
    reg: Register
    version: int = 0

    @property
    def ssa_name(self) -> str:
        return f"{self.reg}_{self.version}"
    
# endregion
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# region Capstone Parser

def parse_bytes_to_function(data: bytes, func_name: str = "main"):

    def parse_operand(op: X86Op) -> Operand:
        parse_reg = lambda reg_id: Register(str(_CS.reg_name(reg_id) or "none").upper())

        if op.type == X86_OP_REG:
            return parse_reg(op.reg)
        
        if op.type == X86_OP_IMM:
            return Immediate(op.imm)
        
        if op.type == X86_OP_MEM:
            return Memory(op.size, parse_reg(op.mem.base), parse_reg(op.mem.index), op.mem.scale, op.mem.disp)
        
        raise ValueError("Unsupported operand type")
    
    def parse_instruction(insn: CsInsn):
        return Instruction(insn.mnemonic, tuple([parse_operand(op) for op in insn.operands]))


    # 1) Decompile data using capstone
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = [i for i in md.disasm(data, 0)]

    # 2) map addr→index and create bounds data struct
    index_map = {i.address: index for index, i in enumerate(insns)}
    leaders = {0}

    # 3) identify basic-block leaders
    for insn in insns:
        if x86_const.X86_GRP_JUMP in insn.groups: continue
        leaders.add(index_map.get(insn.operands[0].imm, 0)) # target address
        if insn.mnemonic == "jmp": continue # unconditional jumps have no fall through
        leaders.add(index_map.get(insn.address + insn.size, 0)) # fall through address

    leaders = sorted(leaders)

    
# endregion
# -----------------------------------------------------------------------------