import re
import fileinput
from collections import namedtuple
# Parser

SPLIT_REGEX = r'[\s|,]'

# Instructions

R_INSTRUCTION = "0b{:06b}{:05b}{:05b}{:05b}{:05b}{:06b}"
I_INSTRUCTION = "0b{:06b}{:05b}{:05b}{:016b}"
#J_INSTRUCTION = "0b{:06b}{:26b}"

Instruction = namedtuple('Instruction', ['format', 'args', 'opcode', 'funct'])

INSTRUCTIONS = {
    'lui':      Instruction('I', ['rt', 'imm'], 0xf, 0x0),
    'addi':     Instruction('I', ['rt', 'rs', 'imm'], 0x8, 0x0),
    'addiu':    Instruction('I', ['rt', 'rs', 'imm'], 0x9, 0x0),
    'slti':     Instruction('I', ['rt', 'rs', 'imm'], 0xa, 0x0),
    'sltiu':    Instruction('I', ['rt', 'rs', 'imm'], 0xb, 0x0),
    'andi':     Instruction('I', ['rt', 'rs', 'imm'], 0xc, 0x0),
    'ori':      Instruction('I', ['rt', 'rs', 'imm'], 0xd, 0x0),
    'xori':     Instruction('I', ['rt', 'rs', 'imm'], 0xe, 0x0),
    'sll':      Instruction('R', ['rd', 'rt', 'shamt'], 0x0, 0x0),
    'srl':      Instruction('R', ['rd', 'rt', 'shamt'], 0x0, 0x2),
    'sra':      Instruction('R', ['rd', 'rt', 'shamt'], 0x0, 0x3),
    'sllv':     Instruction('R', ['rd', 'rt', 'rs'], 0x0, 0x4),
    'srlv':     Instruction('R', ['rd', 'rt', 'rs'], 0x0, 0x6),
    'srav':     Instruction('R', ['rd', 'rt', 'rs'], 0x0, 0x7),
    'mfhi':     Instruction('R', ['rd'], 0x0, 0x10),
    'mthi':     Instruction('R', ['rs'], 0x0, 0x11),
    'mflo':     Instruction('R', ['rd'], 0x0, 0x12),
    'mtlo':     Instruction('R', ['rs'], 0x0, 0x13),
    'mult':     Instruction('R', ['rs', 'rt'], 0x0, 0x18),
    'multu':    Instruction('R', ['rs', 'rt'], 0x0, 0x19),
    'div':      Instruction('R', ['rs', 'rt'], 0x0, 0x1a),
    'divu':     Instruction('R', ['rs', 'rt'], 0x0, 0x1b),
    'add':      Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x20),
    'addu':     Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x21),
    'sub':      Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x22),
    'subu':     Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x23),
    'and':      Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x24),
    'or':       Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x25),
    'xor':      Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x26),
    'nor':      Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x27),
    'slt':      Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x2a),
    'sltu':     Instruction('R', ['rd', 'rs', 'rt'], 0x0, 0x2b)
}

## Registers

def _get_args(letter, lower, upper):
    return ['${}{}'.format(letter,i) for i in range(lower, upper+1)]

ARGS_SYM = (['$zero', '$at']
            + _get_args('v', 0, 1)
            + _get_args('a', 0, 3)
            + _get_args('t', 0, 7)
            + _get_args('s', 0, 7)
            + _get_args('t', 8, 9)
            + _get_args('k', 0, 1)
            + ['$gp', '$sp', '$fp', '$ra'])

ARGS_RAW_MAP = {'${}'.format(i): i for i in range(32)}


ARGS_MAP = dict(zip(ARGS_SYM, range(32)))
ARGS_MAP.update(ARGS_RAW_MAP)

# Parser

def is_comment_or_empty(line):
    return line.strip().startswith('#') or line.isspace()

def are_args_matching(args, instr):
    instr_args = INSTRUCTIONS[instr].args
    return (len(args) == len(instr_args)
            and all(is_arg_matching(arg, instr_arg, instr)
                    for arg, instr_arg in zip(args, instr_args)))

def is_arg_matching(arg, instr_arg, instr):
    return ((arg.startswith('$') and instr_arg.startswith('r') and arg in ARGS_MAP)
            or (arg[0] in '-0123456789' and instr_arg in ['shamt', 'imm']
                and IS_IN_BOUND_VERIFIER[instr_arg](arg, instr)))

def is_shamt(arg, _):
    return 0 <= int(arg) < 32

def is_imm(arg, instr):
    if instr in ['lui']:
        return -2**15 <= int(arg) < 2**16
    if instr in ['xori', 'andi', 'ori']:
        return 0 <= int(arg) < 2**16
    return -2**15 <= int(arg) < 2**15

IS_IN_BOUND_VERIFIER = {'shamt': is_shamt,
                        'imm':   is_imm}

def parse_line(line_number, line):
    try:
        code, comment = (line[:line.index('#')], line[line.index('#'):].strip()) if '#' in line else (line, None)
        instruction, *args = [token for token in re.split(SPLIT_REGEX, code) if token]
    except:
        raise Exception("Syntax error on line {}:{}".format(line_number, line))

    if instruction not in INSTRUCTIONS:
        raise Exception("Unidentified instruction '{}' on line {}:{}".format(instruction, line_number, line))

    try:
        args_match = are_args_matching(args, instruction)
    except ValueError:
        raise Exception("Invalid literal in line {}:{}".format(line_number, line))

    if not args_match:
        raise Exception("Invalid arguments on line {}:{}".format(line_number, line))

    return instruction, args, comment

# Assembler

def translate_line_to_bytes(instruction, args):
    instr_format, *rest = INSTRUCTIONS[instruction]
    return {'R': translate_R_instr_to_bytes,
            'I': translate_I_instr_to_bytes}[instr_format](*rest, args)

def make_shamt(arg):
    return int(arg)

def translate_R_instr_to_bytes(instr_args, opcode, funct, args):
    byte_args = {instr_arg: ARGS_MAP[arg] if arg in ARGS_MAP else make_shamt(arg)
                 for instr_arg, arg in zip(instr_args, args)}

    binary_repr = R_INSTRUCTION.format(opcode,
                                       byte_args.get('rs', 0),
                                       byte_args.get('rt', 0),
                                       byte_args.get('rd', 0),
                                       byte_args.get('shamt', 0),
                                       funct)
    return format(eval(binary_repr), '08X')

def make_imm(arg):
    if int(arg) < 0: # Convert to U2
        bits = "".join(str(1 - int(char)) for char in format(abs(int(arg)), '016b'))
        return eval('0b' + bits) + 1
    return int(arg)

def translate_I_instr_to_bytes(instr_args, opcode, _, args):
    byte_args = {instr_arg: ARGS_MAP[arg] if arg in ARGS_MAP else make_imm(arg)
                 for instr_arg, arg in zip(instr_args, args)}

    binary_repr = I_INSTRUCTION.format(opcode,
                                       byte_args.get('rs', 0),
                                       byte_args.get('rt', 0),
                                       byte_args.get('imm', 0))
    return format(eval(binary_repr), '08X')

def line_number_generator():
    i = 0
    while True:
        yield i
        i += 1

def line_address(i):
    return format(4*i, '08x')

if __name__ == '__main__':
    program = ['.text']
    i_gen = line_number_generator()
    for line in fileinput.input():
        if not is_comment_or_empty(line):
            i = next(i_gen)
            instr, args, comment = parse_line(i, line)
            program.append("\t".join([line_address(i), translate_line_to_bytes(instr, args), "{}\t{} {}".format(instr, ",".join(args), comment) if comment else "{}\t{}".format(instr,",".join(args))]))

    print("\n".join(program))
