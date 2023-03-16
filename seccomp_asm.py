# All instrcutions' name come from 
# https://www.kernel.org/doc/Documentation/networking/filter.txt
# Including,
#   Instruction      Addressing mode      Description
#   ld               1, 2, 3, 4, 12       Load word into A
#   ldi              4                    Load word into A
#   ldh              1, 2                 Load half-word into A
#   ldb              1, 2                 Load byte into A
#   ldx              3, 4, 5, 12          Load word into X
#   ldxi             4                    Load word into X
#   ldxb             5                    Load byte into X
#   st               3                    Store A into M[]
#   stx              3                    Store X into M[]
#   jmp              6                    Jump to label
#   ja               6                    Jump to label
#   jeq              7, 8, 9, 10          Jump on A == <x>
#   jneq             9, 10                Jump on A != <x>
#   jne              9, 10                Jump on A != <x>
#   jlt              9, 10                Jump on A <  <x>
#   jle              9, 10                Jump on A <= <x>
#   jgt              7, 8, 9, 10          Jump on A >  <x>
#   jge              7, 8, 9, 10          Jump on A >= <x>
#   jset             7, 8, 9, 10          Jump on A &  <x>
#   add              0, 4                 A + <x>
#   sub              0, 4                 A - <x>
#   mul              0, 4                 A * <x>
#   div              0, 4                 A / <x>
#   mod              0, 4                 A % <x>
#   neg                                   !A
#   and              0, 4                 A & <x>
#   or               0, 4                 A | <x>
#   xor              0, 4                 A ^ <x>
#   lsh              0, 4                 A << <x>
#   rsh              0, 4                 A >> <x>
#   tax                                   Copy A into X
#   txa                                   Copy X into A
#   ret              4, 11                Return
# The next table shows addressing formats from the 2nd column:
#   Addressing mode  Syntax               Description
#    0               x/%x                 Register X
#    1               [k]                  BHW at byte offset k in the packet
#    2               [x + k]              BHW at the offset X + k in the packet
#    3               M[k]                 Word at offset k in M[]
#    4               #k                   Literal value stored in k
#    5               4*([k]&0xf)          Lower nibble * 4 at byte offset k in the packet
#    6               L                    Jump label L
#    7               #k,Lt,Lf             Jump to Lt if true, otherwise jump to Lf
#    8               x/%x,Lt,Lf           Jump to Lt if true, otherwise jump to Lf
#    9               #k,Lt                Jump to Lt if predicate is true
#   10               x/%x,Lt              Jump to Lt if predicate is true
#   11               a/%a                 Accumulator A
#   12               extension            BPF extension
# ---
# I would implement part of them to provide infra for pwning
# ld st jxx <add ... rsh> tax txa ret

    #  struct bpf_insn {
	#      u_short	 code;
	#      u_char	 jt;
	#      u_char	 jf;
	#      bpf_u_int32 k;
    #  };

# -------------------------------------------------------------------
# n132,
# Mar. 12th, 2023

from pwn import *
DEFINE = True
DEBUG  = False
if (DEFINE):
    # eBPF opcode encoding
    # --------------------
    # eBPF is reusing most of the opcode encoding from classic to simplify conversion
    # of classic BPF to eBPF. For arithmetic and jump instructions the 8-bit 'code'
    # field is divided into three parts:
    #   +----------------+--------+--------------------+
    #   |   4 bits       |  1 bit |   3 bits           |
    #   | operation code | source | instruction class  |
    #   +----------------+--------+--------------------+
    #   (MSB)                                      (LSB)
    # Three LSB bits store instruction class which is one of:
    #   Classic BPF classes:    eBPF classes:
    #   BPF_LD    0x00          BPF_LD    0x00
    #   BPF_LDX   0x01          BPF_LDX   0x01
    #   BPF_ST    0x02          BPF_ST    0x02
    #   BPF_STX   0x03          BPF_STX   0x03
    #   BPF_ALU   0x04          BPF_ALU   0x04
    #   BPF_JMP   0x05          BPF_JMP   0x05
    #   BPF_RET   0x06          BPF_JMP32 0x06
    #   BPF_MISC  0x07          BPF_ALU64 0x07
    
    BPF_LD    =0x00
    BPF_LDX   =0x01
    BPF_ST    =0x02
    BPF_STX   =0x03
    BPF_ALU   =0x04
    BPF_JMP   =0x05
    BPF_RET   =0x06
    BPF_MISC  =0x07

    BPF_W   =0x00    # /* word */
    BPF_H   =0x08    # /* half word */
    BPF_B   =0x10    # /* byte */
    BPF_DW  =0x18    # /* eBPF only, double word */
    
    BPF_IMM  =0x00  # /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
    BPF_ABS  =0x20
    BPF_IND  =0x40
    BPF_MEM  =0x60
    BPF_LEN  =0x80  # /* classic BPF only, reserved in eBPF */
    BPF_MSH  =0xa0  # /* classic BPF only, reserved in eBPF */
    BPF_XADD =0xc0  # /* eBPF only, exclusive add */
    BPF_JA    =0x00  #/* BPF_JMP only */
    BPF_JEQ   =0x10
    BPF_JGT   =0x20
    BPF_JGE   =0x30
    BPF_JSET  =0x40
    BPF_JNE   =0x50  #/* eBPF only: jump != */
    BPF_JSGT  =0x60  #/* eBPF only: signed '>' */
    BPF_JSGE  =0x70  #/* eBPF only: signed '>=' */
    BPF_CALL  =0x80  #/* eBPF BPF_JMP only: function call */
    BPF_EXIT  =0x90  #/* eBPF BPF_JMP only: function return */
    BPF_JLT   =0xa0  #/* eBPF only: unsigned '<' */
    BPF_JLE   =0xb0  #/* eBPF only: unsigned '<=' */
    BPF_JSLT  =0xc0  #/* eBPF only: signed '<' */
    BPF_JSLE  =0xd0  #/* eBPF only: signed '<=' */
    BPF_ADD   =0x00
    BPF_SUB   =0x10
    BPF_MUL   =0x20
    BPF_DIV   =0x30
    BPF_OR    =0x40
    BPF_AND   =0x50
    BPF_LSH   =0x60
    BPF_RSH   =0x70
    BPF_NEG   =0x80
    BPF_MOD   =0x90
    BPF_XOR   =0xa0
    BPF_MOV   =0xb0  #/* eBPF only: mov reg to reg */
    BPF_ARSH  =0xc0  #/* eBPF only: sign extending shift right */
    BPF_END   =0xd0  #/* eBPF only: endianness conversion */
    BPF_X = 0x08
    BPF_K = 0x00
def panic(s):
    print("[!] PANIC: "+s)
    exit(1)
def asm_af(s):
    # return the addressing format
    if s.startswith("#"):
        return 4
    elif s.startswith("M[") and s.endswith("]"):
        return 3
    elif s.startswith("[") and s.endswith("]") and "+" in s:
        return 2
    elif s.startswith("[") and s.endswith("]") and " " not in s:
        return 1
    else:
        panic("ASM ADDR FORMAT-> {}".format(s))
def s2i(arg):
    if arg.startswith("0x"):
        return int(arg,16)
    else:
        return int(arg)
def asm_ld(s):
    # For load and store instructions the 8-bit 'code' field is divided as:
    # +--------+--------+-------------------+
    # | 3 bits | 2 bits |   3 bits          |
    # |  mode  |  size  | instruction class |
    # +--------+--------+-------------------+
    # (MSB)                             (LSB)
    BPF_JF = 0
    BPF_JT = 0
    ldx = BPF_LDX if (s[2]=="X" or s[2]=="x") else 0
    if s[-3:] == "LEN" or s[-3:] == "len":
        BPF_CODE    = BPF_LEN | BPF_W | BPF_LD | ldx
        return p16(BPF_CODE)+p8(BPF_JT)+p8(BPF_JF)+p32(0)
    if s[3] == " ":
        arg = s[4:]
    else:
        arg = s[3:]
    af = asm_af(arg)
    # Simple Implementation: Only Consider `word` 
    if af == 1:
        BPF_CODE    = BPF_ABS | BPF_W | BPF_LD | ldx
        k       = s2i(arg[1:-1])
    elif af == 2:
        BPF_CODE    = BPF_IND | BPF_B | BPF_LD | ldx
        k       = s2i(arg[1:-1].split("+")[-1].strip())
    elif af == 3:
        BPF_CODE    = BPF_MEM | BPF_W | BPF_LD | ldx
        k       = s2i(arg[2:-1])
    elif af == 4:
        BPF_CODE    = BPF_IMM | BPF_W | BPF_LD | ldx
        k       = s2i(arg[1:])
    else:
        panic("ASM_LD-> {}".format(s))
    if DEBUG:
        op = "BPF_LDX" if ldx else "BPF_LD"
        # print(f"[+] {op.ljust(0x10)} => {hex(BPF_CODE).ljust(0x10)}{hex(BPF_JT).ljust(0x10)}{hex(BPF_JF).ljust(0x10)}{hex(k).ljust(0x10)}")
    return p16(BPF_CODE)+p8(BPF_JT)+p8(BPF_JF)+p32(k)
def asm_st(s):
    bpfclass = BPF_STX if s[2]=="x" or s[2]=='X' else BPF_ST
    arg = s[4:]
    assert(arg[:2]=="M[" and arg[-1]==']') 
    idx = s2i(arg[2:-1])
    BPF_JT = 0
    BPF_JF = 0
    k  = idx
    BPF_CODE = BPF_MEM | BPF_W | BPF_LD | bpfclass
    return p16(BPF_CODE)+p8(BPF_JT)+p8(BPF_JF)+p32(k)
def asm_jmp(s):
    # only consider jeq and jne
    # only consider BPF_K
    args = s.strip().split(" ")[1:]
    BPF_JT = s2i(args[0])
    BPF_JF = s2i(args[1])
    if len(args) == 3 :
        source = BPF_K
    else:
        source = BPF_X
    if s.startswith("jeq") or s.startswith('JEQ'):
        BPF_CODE = BPF_JEQ | source | BPF_JMP
    elif s.startswith("jne") or s.startswith("JNE"):
        BPF_CODE = BPF_JNE | source | BPF_JMP
    elif s.startswith("jls") or s.startswith("JLE"):
        BPF_CODE = BPF_JLE | source | BPF_JMP
    else:
        panic("ASM_JMP-> {}".format(s))
    if source == BPF_K:
        return p16(BPF_CODE)+p8(BPF_JT)+p8(BPF_JF)+p32(s2i(args[2]))
    else:
        return p16(BPF_CODE)+p8(BPF_JT)+p8(BPF_JF)+p32(0)
def asm_alu(s):
    # Only support few operation and BPF_X
    BPF_JT  = BPF_JF = 0
    args    = s.strip().split(" ")
    op      = args[0]
    k   = s2i(args[1])
    if op == "AND" or op == "and":
        BPF_CODE = BPF_AND | BPF_K | BPF_ALU
    elif op == "SHR" or op == "shr":
        BPF_CODE = BPF_RSH | BPF_K | BPF_ALU
    else:
        panic("ASM_ALU-> {}".endswithformat(s))
    return p16(BPF_CODE)+p8(BPF_JT)+p8(BPF_JF)+p32(k)
def asm_ret(s):
    args    = s.strip().split(" ")
    BPF_JT = BPF_JF = 0
    k = 0
    BPF_CODE = BPF_RET
    if args[1] == 'ALLOW' or args[1] == "allow":
        k = 0x7fff0000
    elif args[1] == 'ERROR' or args[1] == "error":
        error_code = s2i(args[2])
        k = 0x00050000 + error_code
    else:
        panic("ASM_RET-> {}".format(s))
    return p16(BPF_CODE)+p8(BPF_JT)+p8(BPF_JF)+p32(k)
def asm_misc(s):
    BPF_CODE = BPF_MISC
    BPF_JT = BPF_JF = 0
    if s[0] == "A" or s[0]=='a': # a2x
        return p16(BPF_CODE | 0x80)+p8(BPF_JT)+p8(BPF_JF)+p32(0)
    else:
        return p16(BPF_CODE)+p8(BPF_JT)+p8(BPF_JF)+p32(0)
def parse(s):
    if s.startswith("ld") or s.startswith("LD"):
        return asm_ld(s)
    elif s.startswith("st") or s.startswith("ST"):
        return asm_st(s)
    elif s.startswith("j") or s.startswith("J"):
        return asm_jmp(s)
    elif s.startswith("ret") or s.startswith("RET"):
        return asm_ret(s)
    elif s.startswith("A2X") or s.startswith("X2A") or\
         s.startswith("x2a") or s.startswith('a2x'):
        return asm_misc(s)
    else:
        return asm_alu(s)

    
def asm(s):
    res = b''
    if type(s) == type(b''):
        s = s.decode()
    lines = [x.strip() for x in s.split("\n") if x.strip()!="" ]
    for _ in lines:
        res+= parse(_)
    return res
if __name__ == "__main__":
    pass
    print("n132")