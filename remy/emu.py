from typing import BinaryIO
import elftools.elf.constants
import elftools.elf.relocation
import elftools.elf.elffile
from unicorn import *
from unicorn.arm64_const import *

from .hbabi import LoaderConfigKey, LoaderConfigEntry

def elf_flags_to_uc_prot(flags: int) -> int:
	uc_flags = 0
	if flags & elftools.elf.constants.P_FLAGS.PF_R:
		uc_flags |= UC_PROT_READ
	if flags & elftools.elf.constants.P_FLAGS.PF_W:
		uc_flags |= UC_PROT_WRITE
	if flags & elftools.elf.constants.P_FLAGS.PF_X:
		uc_flags |= UC_PROT_EXEC
	return uc_flags

def humanize_uc_prot(prot: int) -> str:
	return f"{'r' if prot & UC_PROT_READ else '-'}{'w' if prot & UC_PROT_WRITE else '-'}{'x' if prot & UC_PROT_EXEC else '-'}"

def round_up(n: int, multiple: int) -> int:
	return ((n + multiple - 1) // multiple) * multiple

REGMAP = {
	"PC": UC_ARM64_REG_PC,
	"FP": UC_ARM64_REG_FP,
	"LR": UC_ARM64_REG_LR,
	"SP": UC_ARM64_REG_SP,

	"X0": UC_ARM64_REG_X0,
	"X1": UC_ARM64_REG_X1,
	"X2": UC_ARM64_REG_X2,
	"X3": UC_ARM64_REG_X3,
	"X4": UC_ARM64_REG_X4,
	"X5": UC_ARM64_REG_X5,
	"X6": UC_ARM64_REG_X6,
	"X7": UC_ARM64_REG_X7,
	"X8": UC_ARM64_REG_X8,
	"X9": UC_ARM64_REG_X9,
	"X10": UC_ARM64_REG_X10,
	"X11": UC_ARM64_REG_X11,
	"X12": UC_ARM64_REG_X12,
	"X13": UC_ARM64_REG_X13,
	"X14": UC_ARM64_REG_X14,
	"X15": UC_ARM64_REG_X15,
	"X16": UC_ARM64_REG_X16,
	"X17": UC_ARM64_REG_X17,
	"X18": UC_ARM64_REG_X18,
	"X19": UC_ARM64_REG_X19,
	"X20": UC_ARM64_REG_X20,
	"X21": UC_ARM64_REG_X21,
	"X22": UC_ARM64_REG_X22,
	"X23": UC_ARM64_REG_X23,
	"X24": UC_ARM64_REG_X24,
	"X25": UC_ARM64_REG_X25,
	"X26": UC_ARM64_REG_X26,
	"X27": UC_ARM64_REG_X27,
	"X28": UC_ARM64_REG_X28,
	"X29": UC_ARM64_REG_X29,
	"X30": UC_ARM64_REG_X30,
}

class SwitchProcess:
	ASLR_BASE = 0x10_0000  # match ghidra for ez debugging
	PAGE_SIZE = 0x1000

	STACK_START = 0x0ffff_fffdc000
	STACK_END   = 0x10000_00000000

	def __init__(self, elffile: BinaryIO) -> None:
		self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
		entrypoint = self.load_elf(self.ASLR_BASE, elffile)

		# set up the stack
		self.mu.mem_map(self.STACK_START, self.STACK_END - self.STACK_START)
		self.mu.reg_write(UC_ARM64_REG_SP, self.STACK_END - 0x2000)

		# "homebrew ABI" stuff https://switchbrew.org/wiki/Homebrew_ABI
		hbabi = b""
		hbabi += bytes(LoaderConfigEntry(LoaderConfigKey.MainThreadHandle, 0, (0xdeadbeef, 0))) # TODO
		hbabi += bytes(LoaderConfigEntry(LoaderConfigKey.AppletType, 0, (0, 0))) # Application
		hbabi += bytes(LoaderConfigEntry(LoaderConfigKey.EndOfList, 0, (0, 0)))

		hb_args = self.STACK_END - len(hbabi)
		self.mu.mem_write(hb_args, hbabi)

		self.mu.reg_write(UC_ARM64_REG_X0, hb_args)
		self.mu.reg_write(UC_ARM64_REG_X1, 0xFFFFFFFFFFFFFFFF)
		self.mu.reg_write(UC_ARM64_REG_PC, entrypoint)

		# hook syscalls
		self.mu.hook_add(UC_HOOK_INTR, self.hook_syscall)

		# instruction-level tracing
		self.mu.hook_add(UC_HOOK_CODE, self.hook_code)

	def hook_syscall(self, mu: Uc, intno: int, user_data):
		print("syscall", hex(intno))
		if intno == 2:  # SetMemoryPermission
			address = mu.reg_read(UC_ARM64_REG_X0)
			size = mu.reg_read(UC_ARM64_REG_X1)
			perm = mu.reg_read(UC_ARM64_REG_W2)
			print(f"SVC SetMemoryPermission({hex(address)}, {hex(size)}, {perm})")
			mu.reg_write(UC_ARM64_REG_W0, 0)
		else:
			print("unhandled syscall, stopping")
			mu.emu_stop()

	def hook_code(self, mu: Uc, address: int, size: int, user_data):
		print("hook_code", hex(address))

	def load_elf(self, load_base: int, elffile: BinaryIO) -> int:
		elf = elftools.elf.elffile.ELFFile(elffile)

		# process LOAD segments
		for segment in elf.iter_segments("PT_LOAD"):
			hdr = segment.header
			base = load_base + hdr.p_vaddr
			prot = elf_flags_to_uc_prot(hdr.p_flags)
			print(f"mapping {hex(base)} - {hex(base + hdr.p_memsz)} {humanize_uc_prot(prot)}")
			self.mu.mem_map(base, round_up(hdr.p_memsz, self.PAGE_SIZE), prot)
			self.mu.mem_write(base, segment.data())

		# do relocations (assume compiled with modern toolchain that uses relr instead of rela!)
		relrdyn = elf.get_section_by_name(".relr.dyn")
		if not isinstance(relrdyn, elftools.elf.relocation.RelrRelocationSection):
			raise TypeError("unexpected")

		# XXX: not yet confident I'm doing this correctly
		for reloc in relrdyn.iter_relocations():
			offset = load_base + reloc.entry.r_offset
			addend = int.from_bytes(self.mu.mem_read(offset, 8), "little")
			relocated = load_base + addend
			self.mu.mem_write(offset, relocated.to_bytes(8, "little"))

		return load_base + elf.header.e_entry

	def run(self):
		try:
			self.mu.emu_start(self.mu.reg_read(UC_ARM64_REG_PC), 0)
		except Exception as e:
			print()
			print("Exception:", e)
			print()
			for regname, regid in REGMAP.items():
				print(f"{regname:<3}: 0x{self.mu.reg_read(regid):016x}")

			print()
			print("STACK:")
			stack = self.mu.mem_read(self.mu.reg_read(UC_ARM64_REG_SP), 0x100)
			for i in range(0, len(stack), 8):
				print(f"SP+0x{i:04x}: 0x{int.from_bytes(stack[i:i+8], 'little'):016x}")
