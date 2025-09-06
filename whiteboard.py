from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional
from collections import defaultdict
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsInsn, CS_GRP_JUMP
import re
import warnings


# ── IR DATACLASSES ────────────────────────────────────────────────────────────

@dataclass
class PhiNode:
    """
    Represents a φ‑function for a variable at a block entry.
    'incoming' maps each predecessor block → SSA name coming from that pred.
    """
    var: str
    incoming: Dict["BasicBlock", Optional[str]] = field(default_factory=dict)


@dataclass
class BasicBlock:
    """
    A control‑flow basic block:
      - name: identifier (e.g. start address in hex)
      - instructions: Capstone CsInsn list
      - predecessors / successors: CFG links
      - phi_nodes: var → PhiNode inserted at block top
    """
    name: str
    instructions: List[CsInsn] = field(default_factory=list)
    predecessors: Set["BasicBlock"] = field(default_factory=set)
    successors: Set["BasicBlock"] = field(default_factory=set)
    phi_nodes: Dict[str, PhiNode] = field(default_factory=dict)


@dataclass
class SSAFunction:
    """
    Encapsulates SSA result:
      - basic_blocks: all blocks
      - start_block: entry block (None if empty)
    """
    basic_blocks: List[BasicBlock]
    start_block: Optional[BasicBlock]


# ── SSA CONVERTER ─────────────────────────────────────────────────────────────

class SSAConverter:
    """
    Convert a list of Capstone CsInsn into SSA form via:
      1. Basic‑block splitting
      2. CFG construction
      3. Dominators & dominance‑frontiers
      4. φ‑node placement
      5. Variable renaming
    """

    def __init__(self, instructions: List[CsInsn]):
        # allow empty list
        self.instructions = instructions or []
        # map from instruction address → BasicBlock
        self.bb_map: Dict[int, BasicBlock] = {}
        # list of BasicBlocks in program order
        self.blocks: List[BasicBlock] = []
        # flag to avoid rebuilding CFG
        self.cfg_built = False

    def find_leaders(self) -> Set[int]:
        """
        Identify block leaders:
          - first instruction
          - instruction after a jump/ret (fall‑through)
          - any immediate branch target
        """
        leaders: Set[int] = set()
        if not self.instructions:
            return leaders

        # entry is a leader
        leaders.add(self.instructions[0].address)

        for insn in self.instructions:
            # if jump or ret, next insn is leader
            if insn.group(CS_GRP_JUMP) or insn.mnemonic.startswith('ret'):
                leaders.add(insn.address + insn.size)
            # any immediate operand is a target leader
            for op in insn.operands:
                if op.type == op.IMM:
                    leaders.add(op.imm)

        return leaders

    def split_basic_blocks(self):
        """
        Split instructions into BasicBlock objects at leader addresses.
        """
        if not self.instructions:
            return

        leaders = self.find_leaders()
        curr_bb: Optional[BasicBlock] = None

        for insn in self.instructions:
            # start new block at each leader
            if insn.address in leaders:
                curr_bb = BasicBlock(name=hex(insn.address))
                self.blocks.append(curr_bb)
            # append instruction to current block
            curr_bb.instructions.append(insn)
            # record address→block mapping
            self.bb_map[insn.address] = curr_bb

    def build_cfg(self):
        """
        Build CFG by linking successors & predecessors.
        """
        if self.cfg_built or not self.instructions:
            return

        # ensure blocks exist
        self.split_basic_blocks()

        for bb in self.blocks:
            last = bb.instructions[-1]

            # fall‑through edge
            ft = last.address + last.size
            if ft in self.bb_map:
                bb.successors.add(self.bb_map[ft])

            # explicit branch edges
            if last.group(CS_GRP_JUMP):
                for op in last.operands:
                    if op.type == op.IMM:
                        tgt = op.imm
                        if tgt in self.bb_map:
                            bb.successors.add(self.bb_map[tgt])
                        else:
                            warnings.warn(f"branch target {hex(tgt)} not in any block")

        # populate predecessors
        for bb in self.blocks:
            for succ in bb.successors:
                succ.predecessors.add(bb)

        self.cfg_built = True

    def compute_dominators(self):
        """
        Compute dominators using iterative algorithm:
          Dom(start) = {start}
          Dom(b) = {b} ∪ ⋂ Dom(p) for all preds p
        Also computes immediate dominators idom[b].
        """
        if not self.blocks:
            self.dominators = {}
            self.idom = {}
            return

        self.build_cfg()

        # init: every block dominates every block
        dom = {b: set(self.blocks) for b in self.blocks}
        start = self.blocks[0]
        dom[start] = {start}

        changed = True
        while changed:
            changed = False
            for b in self.blocks:
                if b is start:
                    continue
                # intersect dominators of preds
                new = set(self.blocks)
                for p in b.predecessors:
                    new &= dom[p]
                new.add(b)
                if new != dom[b]:
                    dom[b] = new
                    changed = True

        # store dominators
        self.dominators = dom

        # compute immediate dominators
        idom: Dict[BasicBlock, BasicBlock] = {}
        for b, ds in dom.items():
            if b is start:
                continue
            # choose deepest dominator other than self
            cands = ds - {b}
            if cands:
                idom[b] = max(cands, key=lambda x: len(dom[x]))
        self.idom = idom

    def compute_dom_frontiers(self):
        """
        Compute dominance frontiers DF[b]:
          for each b with ≥2 preds, walk up from preds until idom[b].
        """
        if not self.blocks:
            self.dom_frontiers = {}
            return

        # ensure dominators/idom ready
        self.compute_dominators()

        df: Dict[BasicBlock, Set[BasicBlock]] = {b: set() for b in self.blocks}

        for b in self.blocks:
            if len(b.predecessors) < 2:
                continue
            # for each predecessor, walk up dominator tree
            for p in b.predecessors:
                runner = p
                # stop when runner == idom[b]
                while runner is not self.idom.get(b):
                    df[runner].add(b)
                    runner = self.idom.get(runner)
                    if runner is None:
                        break

        self.dom_frontiers = df

    def place_phi_nodes(self, var_defs: Dict[str, Set[BasicBlock]]):
        """
        Place φ‑nodes for each variable at blocks in its dominance frontier.
        """
        if not self.blocks:
            self.phi_blocks = {}
            return

        self.compute_dom_frontiers()
        self.phi_blocks: Dict[str, Set[BasicBlock]] = {v: set() for v in var_defs}

        for v, defs in var_defs.items():
            work = list(defs)
            while work:
                b = work.pop()
                for d in self.dom_frontiers.get(b, ()):
                    if d not in self.phi_blocks[v]:
                        self.phi_blocks[v].add(d)
                        # create phi with slot per predecessor
                        d.phi_nodes[v] = PhiNode(var=v,
                                                 incoming={p: None for p in d.predecessors})
                        # if v wasn't originally defined here, keep placing
                        if d not in defs:
                            work.append(d)

    def rename_vars(self):
        """
        Rename registers to SSA names by DFS on dominator tree,
        using per‑var stacks and counters. Uses regex for safe replace.
        """
        if not self.blocks:
            return

        # ensure dominators & idom
        self.compute_dominators()

        counter: Dict[str, int] = defaultdict(int)
        stack: Dict[str, List[str]] = defaultdict(list)
        # regex factory to match whole register tokens
        token_re = lambda rn: re.compile(rf'\b{re.escape(rn)}\b')

        def recurse(bb: BasicBlock):
            # rename φ outputs
            for v, phi in bb.phi_nodes.items():
                new_name = f"{v}.{counter[v]}"
                counter[v] += 1
                for p in bb.predecessors:
                    phi.incoming[p] = new_name
                stack[v].append(new_name)

            # rename in instructions
            for insn in bb.instructions:
                reads, writes = insn.regs_access()
                # rename uses
                for r in reads:
                    vn = insn.reg_name(r)
                    if stack[vn]:
                        insn.op_str = token_re(vn).sub(stack[vn][-1], insn.op_str)
                # rename defs
                for r in writes:
                    vn = insn.reg_name(r)
                    new_name = f"{vn}.{counter[vn]}"
                    counter[vn] += 1
                    stack[vn].append(new_name)
                    insn.op_str = token_re(vn).sub(new_name, insn.op_str)

            # recurse on dominator‑tree children
            for c in [x for x in self.blocks if self.idom.get(x) == bb]:
                recurse(c)

            # pop stacks for defs
            for insn in bb.instructions:
                _, writes = insn.regs_access()
                for r in writes:
                    stack[insn.reg_name(r)].pop()
            # pop φ entries
            for v in bb.phi_nodes:
                stack[v].pop()

        # start at entry
        recurse(self.blocks[0])

    def convert_to_ssa(self) -> SSAFunction:
        """
        Full SSA conversion driver:
          - handle empty input
          - build CFG
          - collect var definitions
          - place φ‑nodes
          - rename variables
        """
        if not self.instructions:
            return SSAFunction(basic_blocks=[], start_block=None)

        self.build_cfg()

        # collect where each register is defined
        var_defs: Dict[str, Set[BasicBlock]] = defaultdict(set)
        for b in self.blocks:
            for insn in b.instructions:
                _, writes = insn.regs_access()
                for r in writes:
                    var_defs[insn.reg_name(r)].add(b)

        self.place_phi_nodes(var_defs)
        self.rename_vars()

        return SSAFunction(basic_blocks=self.blocks, start_block=self.blocks[0])




with open("asm_data.txt", 'r') as f:
    data = bytes.fromhex(f.read())

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

converter = SSAConverter([i for i in md.disasm(data, 0)])
ssa_fn = converter.convert_to_ssa()

for bb in ssa_fn.basic_blocks:
    print(f"Block {bb.name}")
    for v, mapping in bb.phi_nodes.items():
        print("  φ", v, "=", mapping)
    for insn in bb.instructions:
        print(" ", f"{insn.address:04x}:", insn.mnemonic, insn.op_str)