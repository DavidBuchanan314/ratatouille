from dataclasses import dataclass
from enum import Enum

class LoaderConfigKey(Enum):
	EndOfList = 0  # Must be present
	MainThreadHandle = 1  # Must be present
	NextLoadPath = 2
	OverrideHeap = 3  # If present, must not be ignored
	OverrideService = 4
	Argv = 5
	SyscallAvailableHint = 6
	AppletType = 7  # Must be present
	AppletWorkaround = 8  # If present, must not be ignored
	Reserved9 = 9
	ProcessHandle = 10
	LastLoadResult = 11
	AllocPages = 12
	LockRegion = 13  # If present, must not be ignored
	RandomSeed = 14
	UserIdStorage = 15
	HosVersion = 16
	SyscallAvailableHint2 = 17

class LoaderConfigFlags:
	IsMandatory = 1 << 0

@dataclass(frozen=True)
class LoaderConfigEntry:
	key: LoaderConfigKey
	flags: int
	value: tuple[int, int]

	def __bytes__(self) -> bytes:
		return self.key.value.to_bytes(4, "little") \
			+ self.flags.to_bytes(4, "little") \
			+ self.value[0].to_bytes(8, "little") \
			+ self.value[1].to_bytes(8, "little") 
