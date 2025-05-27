import argparse
from .emu import SwitchProcess

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("elf", help="path to the ELF file to execute")
	args = parser.parse_args()
	with open(args.elf, "rb") as elffile:
		proc = SwitchProcess(elffile)
		proc.run()

if __name__ == "__main__":
	main()
