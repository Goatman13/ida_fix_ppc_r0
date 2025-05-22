import idaapi
import ida_ida
import ida_allins
import ida_idp
import ida_bytes
import ida_ua
import ida_xref

class PPCFIX_disassemble(idaapi.IDP_Hooks):

	def __init__(self):
		idaapi.IDP_Hooks.__init__(self)

	def decode_instruction(self, insn, dword):
		imm = dword & 0xFFFF
		insn.Op1.type = ida_ua.o_idpspec1
		insn.Op1.reg = (dword >> 21) & 0x1F
		insn.Op2.type = ida_ua.o_mem
		if imm > 0x7FFF:
			imm = imm | 0xFFFFFFFFFFFF0000
		insn.Op2.addr = imm
		insn.size = 4

	def ev_emu_insn(self, insn):
		if ((insn.itype == ida_allins.PPC_ld or insn.itype == ida_allins.PPC_std) and ida_bytes.get_wide_dword(insn.ea) & 0x001F0000 == 0):
			if (insn.Op2.type == ida_ua.o_mem and insn.itype == ida_allins.PPC_ld):
				insn.add_cref(insn.ea + insn.size, 0, 21) # 21 Ordinary flow
				insn.add_dref(insn.Op2.addr, 0, ida_xref.dr_R)
				return 1
			elif (insn.Op2.type == ida_ua.o_mem and insn.itype == ida_allins.PPC_std):
				insn.add_cref(insn.ea + insn.size, 0, 21) # 21 Ordinary flow
				insn.add_dref(insn.Op2.addr, 0, ida_xref.dr_W)
				return 1
		return 0

	def ev_ana_insn(self, insn):
		dword = ida_bytes.get_wide_dword(insn.ea)
		opcode = dword >> 26 & 0x3F
		ra = dword >> 16 & 0x1F
		
		# Fix only when RA == r0
		if (opcode == 58 and ra == 0):
			insn.itype = ida_allins.PPC_ld
			self.decode_instruction(insn, dword)
		elif (opcode == 62 and ra == 0):
			insn.itype = ida_allins.PPC_std
			self.decode_instruction(insn, dword)
		else:
			return 0
		return insn.size
		
	def ev_out_operand(self, ctx, op):

		if (op.type == ida_ua.o_idpspec1):
			if (ctx.insn.itype == ida_allins.PPC_ld or ctx.insn.itype == ida_allins.PPC_std):
				ctx.out_register("r%d" % op.reg)
			else:
				return 0
			return 1
		return 0

	def ev_out_mnem(self, ctx):
		
		if (ctx.insn.itype == ida_allins.PPC_ld):
			ctx.out_custom_mnem("ld", 10, "")
			return 1
		if (ctx.insn.itype == ida_allins.PPC_std):
			ctx.out_custom_mnem("std", 10, "")
			return 1
		return 0

class ppcfixup_plugin_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = ""
	help = ""
	wanted_name = "PPC ld/std Fix"
	wanted_hotkey = ""

	def __init__(self):
		self.ppcfix = None

	def init(self):
		if (idaapi.ph.id == idaapi.PLFM_PPC):
			self.ppcfix = PPCFIX_disassemble()
			self.ppcfix.hook()
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP

	def run(self, arg):
		pass

	def term(self):
		if (self.ppcfix != None):
			self.ppcfix.unhook()
			self.ppcfix = None

def PLUGIN_ENTRY():
	return ppcfixup_plugin_t()
