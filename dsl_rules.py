from dsl_helpers import *
from dsl import Rule

stack_push_rsp_rule = Rule(
    name="Stack Push RSP Optimization",
    pattern=[
        create_pattern("sub", "rsp", "0x8"),
        create_pattern("mov", "[rsp]", "rsp"),
        create_pattern("add", "[rsp]", "0x8"),
    ],
    replace_func=lambda bindings: [
        create_instruction("push", "rsp")
    ]
)
stack_pop_rsp_rule = Rule(
    name="Stack Pop RSP Optimization",
    pattern=[
        create_pattern("mov", "rsp", "[rsp]"),
    ],
    replace_func=lambda bindings: [
        create_instruction("pop", "rsp")
    ]
)
stack_push_rule = Rule(
    name="Stack Push Optimization",
    pattern=[
        create_pattern("sub", "rsp", "0x8"),
        create_pattern("mov", "[rsp]", "?src"),
    ],
    replace_func=lambda bindings: [
        create_instruction("push", bindings["src"]),
    ]
)
stack_pop_rule = Rule(
    name="Stack Pop Optimization",
    pattern=[
        create_pattern("mov", "?dst", "[rsp]"),
        create_pattern("add", "rsp", "0x8"),
    ],
    replace_func=lambda bindings: [
        create_instruction("pop", bindings["dst"]),
    ]
)
redundant_mov_rule = Rule(
    name="Eliminate Redundant MOV",
    pattern=[create_pattern("mov", "?x", "?x")],
    replace_func=lambda bindings: [
        create_nop()
    ]
)
redundant_inc_dec_rule = Rule(
    name="Eliminate Redundant INC/DEC",
    pattern=[
        create_pattern("inc", "?dst"),
        create_pattern("dec", "?dst"),
    ],
    replace_func=lambda bindings: [
        create_nop()
    ]
)
redundant_xor_rule = Rule(
    name="Eliminate Redundant XOR",
    pattern=[
        create_pattern("xor", "?dst", "?src"),
        create_pattern("xor", "?dst", "?src"),
    ],
    replace_func=lambda bindings: [
        create_nop()
    ]
)
push_pop_simplification_rule = Rule(
    name="Simplify PUSH-POP Sequence",
    pattern=[
        create_pattern("push", "?src"),
        create_pattern("pop", "?dst"),
    ],
    replace_func=lambda bindings:[
        create_instruction("mov", bindings["dst"], bindings["src"])
    ]
)
mem_arithmetic_rule = Rule(
    name="Optimize Memory Arithmetic",
    pattern=[
        create_pattern("push", "?reg"),
        create_pattern(["add", "sub"], "[rsp]", "?imm"),
        create_pattern("pop", "?reg"),
    ],
    replace_func=lambda bindings: [
        create_instruction(bindings["opcode"], bindings["reg"], bindings["imm"]),
    ]
)
overwrite_push_rule = Rule(
    name="Optimize Overwritten PUSH",
    pattern=[
        create_pattern("push"),
        create_pattern("mov", "[rsp]", "?src"),
    ],
    replace_func=lambda bindings: [
        create_instruction("push", bindings["src"]),
    ]
)
redundant_add_sub_rule = Rule(
    name="Eliminate Redundant ADD/SUB",
    pattern=[
        create_pattern("add", "?dst", "?src"),
        create_pattern("sub", "?dst", "?src"),
    ],
    replace_func=lambda bindings: [
        create_nop()
    ]
)
redundant_sub_add_rule = Rule(
    name="Eliminate Redundant SUB/ADD",
    pattern=[
        create_pattern("sub", "?dst", "?src"),
        create_pattern("add", "?dst", "?src"),
    ],
    replace_func=lambda bindings: [
        create_nop()
    ]
)
wrapped_redundant_add_sub_rule = Rule(
    name="Optimize Wrapped Math Operations",
    pattern=[
        create_pattern("sub", "?dst", "?src"),
        create_pattern(["sub", "add"], "?dst", "?main_src"),
        create_pattern("add", "?dst", "?src"),
    ],
    replace_func=lambda bindings:[
        create_instruction(bindings["opcode"], bindings["dst"], bindings["main_src"])
    ]
)
wrapped_redundant_sub_add_rule = Rule(
    name="Optimize Wrapped Math Operations",
    pattern=[
        create_pattern("add", "?dst", "?src"),
        create_pattern(["sub", "add"], "?dst", "?main_src"),
        create_pattern("sub", "?dst", "?src"),
    ],
    replace_func=lambda bindings:[
        create_instruction(bindings["opcode"], bindings["dst"], bindings["main_src"])
    ]
)
split_add_rule = Rule(
    name="Optimize Split ADD Operations",
    pattern=[
        create_pattern("push", "?src"),
        create_pattern(["add", "sub", "xor"], "[rsp]", "?val"),
        create_pattern("pop", "?dst"),
    ],
    replace_func=lambda bindings: [
        create_instruction("mov", bindings["dst"], bindings["src"]),
        create_instruction(bindings["opcode"], bindings["dst"], bindings["val"]),
    ]
)

memory_move_simplification_rule = Rule(
    name="Optimize Memory Move Operations",
    pattern=[
        create_pattern("push", "?temp"),
        create_pattern("mov", "?temp", "?src"),
        create_pattern(["add", "sub", "xor", "mov"], "[rsp+0x8]", "?temp"),
        create_pattern("pop", "?temp"),
    ],
    replace_func=lambda bindings: [
        create_instruction(bindings["opcode"], "[rsp]", bindings["src"]),
    ]
)
stack_pointer_add_rule = Rule(
    name="Optimize RSP ADD Sequences",
    pattern=[
        create_pattern("push", "?temp"),
        create_pattern("mov", "?temp", "rsp"),
        create_pattern("add", "?temp", "0x8"),
        create_pattern("add", "?temp", "0x8"),
        create_pattern("xchg", "[rsp]", "?temp"),
        create_pattern("pop", "rsp"),
    ],
    replace_func=lambda bindings: [
        create_instruction("add", "rsp", "0x8")
    ]
)
stack_pointer_sub_rule = Rule(
    name="Optimize RSP SUB Sequences",
    pattern=[
        create_pattern("push", "?temp"),
        create_pattern("mov", "?temp", "rsp"),
        create_pattern("xchg", "[rsp]", "?temp"),
        create_pattern("pop", "rsp"),
    ],
    replace_func=lambda bindings: [
        create_instruction("sub", "rsp", "0x8")
    ]
)
xor_to_xchg_rule = Rule(
    name="Convert XOR Swap to XCHG",
    pattern=[
        create_pattern("xor", "?src", "?dst"),
        create_pattern("xor", "?dst", "?src"),
        create_pattern("xor", "?src", "?dst"),
    ],
    replace_func=lambda bindings: [
        create_instruction("xchg", bindings["dst"], bindings["src"]),
    ]
)
redundant_stack_manipulation_rule = Rule(
    name="Eliminate Redundant Stack Manipulation",
    pattern=[
        create_pattern("push", "?temp"),
        create_pattern("mov", "?temp", "rsp"),
        create_pattern("xchg", "[rsp]", "?temp"),
        create_pattern("mov", "rsp", "[rsp]"),
    ],
    replace_func=lambda bindings: [
        create_instruction("push", bindings["temp"]),
    ]
)
split_xchg_rule = Rule(
    name="Simplify Stack Exchange",
    pattern=[
        create_pattern("push", "?src"),
        create_pattern("mov", "?src", "[rsp+0x8]"),
        create_pattern("pop", "[rsp]"),
    ],
    replace_func=lambda bindings: [
        create_instruction("xchg", "[rsp]", bindings["src"]),
    ]
)
delayed_push_optimization_rule = Rule(
    name="Optimize Delayed PUSH Sequences",
    pattern=[
        create_pattern("sub", "rsp", "0x8"),
        create_pattern("push", "?late"),
        create_pattern("mov", "?late", "?early"),
        create_pattern("mov", "[rsp+0x8]", "?late"),
        create_pattern("mov", "?late", "[rsp]")
    ],
    replace_func=lambda bindings: [
        create_instruction("push", bindings["early"]),
        create_instruction("push", bindings["late"]),
    ]
)
redundant_push_add_rule = Rule(
    name="Remove Redundant Stack Adjustments",
    pattern=[
        create_pattern("push"),
        create_pattern("add", "rsp", "0x8"),
    ],
    replace_func=lambda bindings: [
        create_nop(),
    ]
)
simplify_not_rule = Rule(
    name="Simplify NOT Instruction",
    pattern=[
        create_pattern("not", "?operand"),
    ],
    replace_func=lambda bindings: [
        create_instruction("xor", bindings["operand"], "0xFFFFFFFFFFFFFFFF"),
    ]
)
simplify_inc_rule = Rule(
    name="Replace INC with ADD",
    pattern=[
        create_pattern("inc", "?operand"),
    ],
    replace_func=lambda bindings: [
        create_instruction("add", bindings["operand"], "0x1"),
    ]
)
simplify_dec_rule = Rule(
    name="Convert DEC to ADD",
    pattern=[
        create_pattern("dec", "?operand"),
    ],
    replace_func=lambda bindings: [
        create_instruction("add", bindings["operand"], "0xFFFFFFFFFFFFFFFF"),
    ]
)
combined_mov_math_rule = Rule(
    name="Fold Immediate Math into Move",
    pattern=[
        create_pattern("mov", "?operand", ["IMM", "?start"]),
        create_pattern(["add", "sub", "xor", "shl", "shr"], "?operand", ["IMM", "?val"]),
    ],
    replace_func=lambda bindings: [
        create_instruction("mov", bindings["operand"], "0x" + math_reg(bindings["operand"], bindings["start"], bindings["opcode"], bindings["val"])),
    ]
)
combined_push_math_pop_rule = Rule(
    name="Eliminate Redundant Temp Register Math",
    pattern=[
        create_pattern("push", "?temp"),
        create_pattern("mov", "?temp", "?val"),
        create_pattern("mov", "?reg", "?other"),
        create_pattern(["add", "sub", "xor", "shr", "shl", "mov"], "?reg", "?temp"),
        create_pattern("pop", "?temp")
    ],
    replace_func=lambda bindings: [
        create_instruction("mov", bindings["reg"], bindings["other"]),
        create_instruction(bindings["opcode"], bindings["reg"], bindings["val"]),
    ]
)
combined_mov_mov_rule = Rule(
    name="Combine MOV and Math Operations",
    pattern=[
        create_pattern("push", "?temp"),
        create_pattern("mov", "?temp", "?val"),
        create_pattern("mov", "?reg", "?temp"),
        create_pattern("pop", "?temp")
    ],
    replace_func=lambda bindings: [
        create_instruction("mov", bindings["reg"], bindings["val"]),
    ]
)