from dataclasses import dataclass, field
from typing import List, Optional, Union, Dict, Set
from capstone import CS_ARCH_X86, CS_MODE_64, CsInsn, x86_const, Cs
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

# --- your existing IR definitions (unchanged) ---

@dataclass(frozen=True)
class Register:
    canonical_name: str  # e.g. "rax"
    size: int            # bit‑width, e.g. 64
    offset: int = 0      # sub‑register offset (e.g. 8 for ah)

@dataclass(frozen=True)
class Immediate:
    value: int           # literal constant

@dataclass(frozen=True)
class Memory:
    base: Optional[Register]
    index: Optional[Register]
    scale: Optional[int]
    displacement: Optional[int]
    size: int            # access width in bytes

Operand = Union[Register, Immediate, Memory]

@dataclass
class Instruction:
    opcode: str                   # e.g. "mov", "add"
    operands: List[Operand]       # operand list
    size: int                     # number of bytes it uses

@dataclass
class BasicBlock:
    name: str
    lines: List[Instruction] = field(default_factory=list)
    successors: List["BasicBlock"] = field(default_factory=list)
    predecessors: List["BasicBlock"] = field(default_factory=list)

@dataclass
class Function:
    name: str
    blocks: List[BasicBlock] = field(default_factory=list)


# --- SSA extensions: PhiInstruction and SSA‑specific block/function ---

@dataclass
class PhiInstruction(Instruction):
    args: Dict[str, Register] = field(default_factory=dict)
    def __post_init__(self):
        # Force opcode to "phi" and reserve .args for incoming values
        self.opcode = 'phi'

@dataclass
class SSABasicBlock:
    name: str
    phi_instructions: List[PhiInstruction] = field(default_factory=list)
    lines: List[Instruction] = field(default_factory=list)
    successors: List["SSABasicBlock"] = field(default_factory=list)
    predecessors: List["SSABasicBlock"] = field(default_factory=list)

@dataclass
class SSAFunction:
    name: str
    blocks: List[SSABasicBlock]


# --- The converter class: drives the entire SSA construction ---

class SSAConverter:
    def __init__(self, func: Function):
        self.orig = func
        # Wrap each original block in an SSABasicBlock
        self.blocks: Dict[str, SSABasicBlock] = {
            b.name: SSABasicBlock(name=b.name)
            for b in func.blocks
        }
        # Copy control‐flow edges into the SSA‐blocks
        for b in func.blocks:
            ssab = self.blocks[b.name]
            for s in b.successors:
                ssab.successors.append(self.blocks[s.name])
        # Build reverse edges
        self._compute_predecessors()

        # Data structures for dominators & frontiers:
        self.dom: Dict[str, Set[str]] = {}   # dominator sets
        self.idom: Dict[str, Optional[str]] = {}  # immediate dominator
        self.df: Dict[str, Set[str]] = {}    # dominance frontier

        # For renaming pass:
        self.version_counter: Dict[str, int] = {}
        self.name_stack: Dict[str, List[int]] = {}

    def _compute_predecessors(self):
        ## Clear existing preds, then repopulate from succs
        for sb in self.blocks.values():
            sb.predecessors.clear()
        for sb in self.blocks.values():
            for succ in sb.successors:
                succ.predecessors.append(sb)

    def _compute_dominators(self):
        all_b = set(self.blocks.keys())
        entry = self.orig.blocks[0].name

        # 1) initialize: entry dominates itself; others start as all blocks
        for n in all_b:
            self.dom[n] = all_b.copy()
        self.dom[entry] = {entry}

        # 2) iterate until convergence
        changed = True
        while changed:
            changed = False
            for b in all_b - {entry}:
                # intersect dominators of all predecessors
                preds = self.blocks[b].predecessors
                newdom = all_b.copy()
                for p in preds:
                    newdom &= self.dom[p.name]
                newdom.add(b)            # a block always dominates itself
                if newdom != self.dom[b]:
                    self.dom[b] = newdom
                    changed = True

        # 3) extract immediate dominator for each non‑entry block
        for b in all_b:
            if b == entry:
                self.idom[b] = None
            else:
                candidates = self.dom[b] - {b}
                # pick the one that doesn’t dominate any other candidate
                idom = next(
                    d for d in candidates
                    if all(d == o or d not in self.dom[o] for o in candidates)
                )
                self.idom[b] = idom

    def _compute_df(self):
        # initialize empty frontiers
        for b in self.blocks:
            self.df[b] = set()

        # for each block with ≥2 preds, walk up idom chain
        for b in self.blocks:
            preds = self.blocks[b].predecessors
            if len(preds) < 2:
                continue
            for p in preds:
                runner = p.name
                # every block on path from p up to idom[b] gets b in its DF
                while runner != self.idom[b]:
                    if not runner: raise
                    self.df[runner].add(b)
                    runner = self.idom[runner]

    def _gather_defs(self) -> Dict[str, Set[str]]:
        """
        Walk original instructions; for each non‑phi instr,
        treat its first operand (if a Register) as a def.
        """
        defs: Dict[str, Set[str]] = {}
        for b in self.orig.blocks:
            for instr in b.lines:
                if instr.opcode.lower() == 'phi':
                    continue
                if instr.operands and isinstance(instr.operands[0], Register):
                    var = instr.operands[0].canonical_name
                    defs.setdefault(var, set()).add(b.name)
        return defs

    def _insert_phi(self):
        # For each variable, place φs in frontier blocks
        defs = self._gather_defs()
        for var, def_blocks in defs.items():
            work = list(def_blocks)
            placed: Set[str] = set()
            while work:
                b = work.pop()
                for d in self.df[b]:
                    if d not in placed:
                        # create φ targeting `var` in block d
                        phi = PhiInstruction(opcode="phi", operands=[Register(var, size=0)], size=0)
                        self.blocks[d].phi_instructions.append(phi)
                        placed.add(d)
                        # if new φ-block wasn’t a def-site, re‑enqueue
                        if d not in def_blocks:
                            work.append(d)

    def _rename(self):
        # --- initialize version counters & stacks for each var ---
        for b in self.orig.blocks:
            for instr in b.lines:
                if instr.operands and isinstance(instr.operands[0], Register):
                    v = instr.operands[0].canonical_name
                    self.version_counter.setdefault(v, 0)
                    self.name_stack.setdefault(v, [])
        # push “0” for each var so uses before defs get version 0
        self.name_stack.setdefault("rbp", [])
        for v in self.version_counter:
            self.name_stack[v].append(0)

        # build dominator‐tree children lists
        dom_tree: Dict[str, List[str]] = {b: [] for b in self.blocks}
        for b, i in self.idom.items():
            if i:
                dom_tree[i].append(b)

        def rename_block(bname: str):
            sb = self.blocks[bname]

            # 1) Rename φ‑function definitions
            for phi in sb.phi_instructions:
                if not isinstance(phi.operands[0], Register): raise
                v = phi.operands[0].canonical_name
                nv = self.version_counter[v] + 1
                self.version_counter[v] = nv
                self.name_stack[v].append(nv)
                # rewrite φ’s target to v_nv
                phi.operands[0] = Register(f"{v}_{nv}", size=0)

            # 2) Rename ordinary instructions (in original order)
            orig_blk = next(b for b in self.orig.blocks if b.name == bname)
            for instr in orig_blk.lines:
                # rewrite uses (every register operand)
                for i, op in enumerate(instr.operands):
                    if isinstance(op, Register):
                        v = op.canonical_name
                        ver = self.name_stack[v][-1]
                        instr.operands[i] = Register(f"{v}_{ver}", size=op.size)
                # rewrite def (first operand) to new version
                if instr.operands and isinstance(instr.operands[0], Register):
                    v = instr.operands[0].canonical_name
                    v = v.split('_', 1)[0]
                    nv = self.version_counter[v] + 1
                    self.version_counter[v] = nv
                    self.name_stack[v].append(nv)
                    instr.operands[0] = Register(f"{v}_{nv}", size=instr.operands[0].size)
                # append renamed instr into SSA block
                sb.lines.append(instr)

            # 3) Update φ‑args in each successor
            for succ in sb.successors:
                for phi in succ.phi_instructions:
                    if not isinstance(phi.operands[0], Register): raise
                    var = phi.operands[0].canonical_name.split('_')[0]
                    ver = self.name_stack[var][-1]
                    phi.args[bname] = Register(f"{var}_{ver}", size=0)

            # 4) Recurse on children in dominator tree
            for child in dom_tree[bname]:
                rename_block(child)

            # 5) Pop stacks for defs in this block
            for phi in sb.phi_instructions:
                if not isinstance(phi.operands[0], Register): raise
                v = phi.operands[0].canonical_name.split('_')[0]
                self.name_stack[v].pop()
            for instr in orig_blk.lines:
                if instr.operands and isinstance(instr.operands[0], Register):
                    v = instr.operands[0].canonical_name.split('_')[0]
                    self.name_stack[v].pop()

        # start renaming at entry block
        entry = self.orig.blocks[0].name
        rename_block(entry)

    def convert_to_ssa(self) -> SSAFunction:
        # 1) Dominator analysis
        self._compute_dominators()
        # 2) Dominance frontier
        self._compute_df()
        # 3) Place φ‑functions
        self._insert_phi()
        # 4) Rename into SSA
        self._rename()
        # return the new SSAFunction
        return SSAFunction(
            name=self.orig.name,
            blocks=list(self.blocks.values())
        )

def _to_register(cs: Cs, reg_id: int, op_size: int) -> Register:
    name = cs.reg_name(reg_id)
    if not name: raise
    # map common names to bit‐size
    # e.g. al, ah → 8; ax → 16; eax → 32; rax → 64
    size_map = {'8':8, '16':16, '32':32, '64':64}
    for suffix, bits in size_map.items():
        if name.endswith(suffix):
            return Register(canonical_name=name, size=bits, offset=0)
    # fallback: size = op_size * 8
    return Register(canonical_name=name, size=op_size*8, offset=0)

def _to_operand(cs: Cs, op) -> Operand:
    if op.type == X86_OP_REG:
        return _to_register(cs, op.value.reg, op.size)
    elif op.type == X86_OP_IMM:
        return Immediate(value=op.value.imm)
    elif op.type == X86_OP_MEM:
        m = op.value.mem
        base = _to_register(cs, m.base, op.size) if m.base != 0 else None
        index = _to_register(cs, m.index, op.size) if m.index != 0 else None
        scale = m.scale if m.scale != 0 else None
        disp = m.disp if m.disp != 0 else None
        # op.size is number of bytes
        return Memory(base=base, index=index, scale=scale, displacement=disp, size=op.size)
    else:
        raise NotImplementedError(f"Operand type {op.type} not supported")

def parse_insns_to_function(insns: List[CsInsn], func_name: str="sub_x") -> Function:
    """
    Build a Function dataclass from a flat list of CsInsn.
    """
    # 1) collect addresses and map addr→insn
    addr2insn = {i.address: i for i in insns}
    addresses = [i.address for i in insns]
    
    # 2) identify basic‐block leaders
    leaders = set()
    if not addresses:
        return Function(name=func_name, blocks=[])
    leaders.add(addresses[0])
    
    for insn in insns:
        groups = insn.groups
        mnemonic = insn.mnemonic.lower()
        last = insn
        next_addr = insn.address + insn.size
        
        # any direct branch (conditional/unconditional)
        if x86_const.X86_GRP_JUMP in groups:
            # target of the jump
            for op in insn.operands:
                if op.type == X86_OP_IMM:
                    tgt = op.value.imm
                    leaders.add(tgt)
            # fall‑through also starts a block
            if mnemonic.startswith('j') and mnemonic != 'jmp':  # conditional
                leaders.add(next_addr)
            # unconditional jmp: no fall‑through
        # any return
        if x86_const.X86_GRP_RET in groups:
            # next instruction (if any) is a leader
            leaders.add(next_addr)
    
    # only keep leaders that actually exist in our insn list
    leaders &= set(addresses)
    
    # 3) sort leaders and build blocks
    sorted_leaders = sorted(leaders)
    # map leader addr → BasicBlock
    blocks: Dict[int,BasicBlock] = {
        addr: BasicBlock(name=f"block_{addr:x}", lines=[]) for addr in sorted_leaders
    }
    # helper: find block for a given address
    def find_block(addr):
        # leader that is ≤ addr, maximal
        cands = [l for l in sorted_leaders if l <= addr]
        if not cands:
            return None
        leader = max(cands)
        return blocks[leader]
    
    # assign instructions to blocks
    for insn in insns:
        bb = find_block(insn.address)
        if not bb: raise
        bb.lines.append(
            Instruction(
                opcode=insn.mnemonic,
                operands=[ _to_operand(insn._cs, op) for op in insn.operands ],
                size=len(insn.bytes)
            )
        )
    
    # 4) set up successors & predecessors
    for leader, bb in blocks.items():
        if not bb.lines:
            continue
        last_insn = bb.lines[-1]
        # get the original CsInsn to inspect its control‐flow
        cs_insn = addr2insn[leader + sum(i.size for i in bb.lines[:-1])]
        groups = cs_insn.groups
        next_addr = cs_insn.address + cs_insn.size
        
        succ_addrs = []
        # conditional jump: two successors
        if x86_const.X86_GRP_JUMP in groups:
            # find immediate target
            for op in cs_insn.operands:
                if op.type == X86_OP_IMM:
                    succ_addrs.append(op.value.imm)
            # if conditional, also fall‐through
            if cs_insn.mnemonic.lower().startswith('j') and cs_insn.mnemonic.lower() != 'jmp':
                succ_addrs.append(next_addr)
        elif x86_const.X86_GRP_RET in groups:
            succ_addrs = []
        else:
            # fall‐through
            succ_addrs = [ next_addr ] if next_addr in blocks else []
        
        # link successors
        for a in succ_addrs:
            tgt_bb = blocks.get(a)
            if tgt_bb:
                bb.successors.append(tgt_bb)
                tgt_bb.predecessors.append(bb)
    
    # 5) return the Function
    return Function(
        name=func_name,
        blocks=list(blocks.values())
    )


with open("asm_data.txt", 'r') as f:
    data = bytes.fromhex(f.read())

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

func = parse_insns_to_function([i for i in md.disasm(data, 0)], "main")

ssa_fn = SSAConverter(func).convert_to_ssa()

text_data = []

for block in ssa_fn.blocks:
    text_data.append(f"{block.name}:")
    for line in block.phi_instructions:
        op = line.opcode
        left = line.operands[0] if len(line.operands) > 0 else ""
        right = f", {line.operands[1]}" if len(line.operands) > 1 else ""
        text_data.append(f"\t{line.opcode} {left} {right}")

with open("asm_text.txt", 'w') as f:
    f.write("\n".join(text_data))