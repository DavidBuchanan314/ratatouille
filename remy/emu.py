from typing import BinaryIO
import elftools.elf.constants
import elftools.elf.elffile
from unicorn import *
from unicorn.arm64_const import *

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

class SwitchProcess:
	ASLR_BASE = 0x10_0000  # match ghidra for ez debugging
	PAGE_SIZE = 0x1000

	def __init__(self, elffile: BinaryIO) -> None:
		self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
		entrypoint = self.load_elf(self.ASLR_BASE, elffile)

		# TODO: init registers

	def load_elf(self, load_base: int, elffile: BinaryIO) -> int:
		elf = elftools.elf.elffile.ELFFile(elffile)
		for segment in elf.iter_segments("PT_LOAD"):
			hdr = segment.header
			base = load_base + hdr.p_vaddr
			prot = elf_flags_to_uc_prot(hdr.p_flags)
			print(f"mapping {hex(base)} - {hex(base + hdr.p_memsz)} {humanize_uc_prot(prot)}")
			self.mu.mem_map(base, round_up(hdr.p_memsz, self.PAGE_SIZE), prot)
			self.mu.mem_write(base, segment.data())

		# TODO: relocate the ELF

		return load_base + elf.header.e_entry
