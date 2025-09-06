import json
import sys
import subprocess
import tempfile
import os

from unicorn import UC_ARCH_X86, UC_MODE_64
from unicorn.unicorn import Uc
from unicorn.x86_const import * #type: ignore
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# -----------------------------------------------------------------------------
# NASM-based assembly function
# -----------------------------------------------------------------------------
def assemble_with_nasm(asm_code, org_addr):
    """
    Assemble AMD64 assembly source using NASM (producing flat binary).
    We prepend a header with "bits 64" and "org <org_addr>".
    """
    with tempfile.NamedTemporaryFile("w", suffix=".asm", delete=False) as asm_file:
        asm_file.write("bits 64\n")
        asm_file.write("org {}\n".format(org_addr))
        asm_file.write(asm_code)
        asm_file_name = asm_file.name

    bin_file_name = asm_file_name + ".bin"

    try:
        subprocess.check_call(["nasm", "-f", "bin", asm_file_name, "-o", bin_file_name])
    except subprocess.CalledProcessError as e:
        print("NASM assembly failed:", e)
        os.unlink(asm_file_name)
        sys.exit(1)

    with open(bin_file_name, "rb") as f:
        binary = f.read()

    os.unlink(asm_file_name)
    os.unlink(bin_file_name)
    return binary

# -----------------------------------------------------------------------------
# Helper function to dump the stack
# -----------------------------------------------------------------------------
def dump_stack(mu, final_rsp, stack_top):
    """
    Read memory from final_rsp up to stack_top (in 8-byte increments)
    and return a list of qwords.
    """
    stack_dump = []
    size = stack_top - final_rsp
    count = size // 8
    for i in range(count):
        addr = final_rsp + i * 8
        qword = mu.mem_read(addr, 8)
        val = int.from_bytes(qword, byteorder='little')
        stack_dump.append(val)
    return stack_dump

# -----------------------------------------------------------------------------
# Emulation functions using Unicorn and disassembly using Capstone
# -----------------------------------------------------------------------------
def emulate_code(code, config):
    """Emulate assembled code with Unicorn and return final register state and stack dump."""
    code_addr = int(config["code_address"], 0)
    stack_top = int(config["stack_address"], 0)
    stack_size = int(config["stack_size"])
    initial_regs = config["initial_registers"]

    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    code_size = 0xaea000  # Allocate 2KB for code.
    mu.mem_map(code_addr, code_size)
    mu.mem_map(stack_top - stack_size, stack_size)  # Stack memory mapped from (top - size) to top.
    mu.mem_map(int("0x7FFE0000", 0), int("0x1000", 0))

    mu.mem_write(code_addr, code)

    reg_map = {
        "rax": UC_X86_REG_RAX,
        "rbx": UC_X86_REG_RBX,
        "rcx": UC_X86_REG_RCX,
        "rdx": UC_X86_REG_RDX,
        "rsi": UC_X86_REG_RSI,
        "rdi": UC_X86_REG_RDI,
        "rbp": UC_X86_REG_RBP,
        "rsp": UC_X86_REG_RSP,
        "r8":  UC_X86_REG_R8,
        "r9":  UC_X86_REG_R9,
        "r10": UC_X86_REG_R10,
        "r11": UC_X86_REG_R11,
        "r12": UC_X86_REG_R12,
        "r13": UC_X86_REG_R13,
        "r14": UC_X86_REG_R14,
        "r15": UC_X86_REG_R15,
    }
    for reg, val in initial_regs.items():
        if reg.lower() in reg_map:
            mu.reg_write(reg_map[reg.lower()], int(val, 0))

    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    print("Disassembled code at 0x%x:" % code_addr)
    for i in cs.disasm(code, code_addr):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    print()

    try:
        mu.emu_start(code_addr, code_addr + len(code))
    except Exception as e:
        print("Emulation error:", e)
        sys.exit(1)

    final_regs = {}
    for reg, unicorn_const in reg_map.items():
        final_regs[reg] = mu.reg_read(unicorn_const)

    final_rsp = final_regs["rsp"]
    # Dump the stack from final_rsp up to the original stack top.
    stack_dump = dump_stack(mu, final_rsp, stack_top)
    
    return final_regs, stack_dump

def compare_states(state1, state2):
    """Compare two register state dictionaries."""
    diff = {}
    for reg in state1:
        if state1[reg] != state2.get(reg, None):
            diff[reg] = (state1[reg], state2.get(reg))
    return diff

def compare_stacks(stack1, stack2):
    """Compare two stack dumps (lists of qwords)."""
    diff = []
    length = max(len(stack1), len(stack2))
    for i in range(length):
        val1 = stack1[i] if i < len(stack1) else None
        val2 = stack2[i] if i < len(stack2) else None
        if val1 != val2:
            diff.append((i, val1, val2))
    return diff

# -----------------------------------------------------------------------------
# Main execution
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    try:
        with open("Config.json", "r") as f:
            config = json.load(f)
    except Exception as e:
        print("Error reading Config.json:", e)
        sys.exit(1)

    try:
        with open("Raw.txt", "r") as f:
            raw_asm = f.read()
    except Exception as e:
        print("Error reading Raw.txt:", e)
        sys.exit(1)

    try:
        with open("Edit.txt", "r") as f:
            edit_asm = f.read()
    except Exception as e:
        print("Error reading Edit.txt:", e)
        sys.exit(1)

    code_addr = config["code_address"]
    raw_code = assemble_with_nasm(raw_asm, code_addr)
    edit_code = assemble_with_nasm(edit_asm, code_addr)

    print("Emulating Raw.txt ...")
    final_state_raw, stack_raw = emulate_code(raw_code, config)
    print("Final register state (Raw.txt):")
    for reg, val in final_state_raw.items():
        print(f"{reg} = {hex(val)}")
    print("Final stack dump (Raw.txt):")
    for i, word in enumerate(stack_raw):
        print(f"Stack[{i*8:04x}] = {hex(word)}")
    print()

    print("Emulating Edit.txt ...")
    final_state_edit, stack_edit = emulate_code(edit_code, config)
    print("Final register state (Edit.txt):")
    for reg, val in final_state_edit.items():
        print(f"{reg} = {hex(val)}")
    print("Final stack dump (Edit.txt):")
    for i, word in enumerate(stack_edit):
        print(f"Stack[{i*8:04x}] = {hex(word)}")
    print()

    differences = compare_states(final_state_raw, final_state_edit)
    stack_diff = compare_stacks(stack_raw, stack_edit)

    if not differences:
        print("The final register states are identical.")
    else:
        print("Differences found in final registers:")
        for reg, (v1, v2) in differences.items():
            print(f"{reg}: Raw = {hex(v1)}, Edit = {hex(v2)}")

    if not stack_diff:
        print("The final stack contents are identical.")
    else:
        print("Differences found in final stack:")
        for idx, v1, v2 in stack_diff:
            print(f"Offset {idx*8:04x}: Raw = {hex(v1) if v1 is not None else 'None'}, Edit = {hex(v2) if v2 is not None else 'None'}")