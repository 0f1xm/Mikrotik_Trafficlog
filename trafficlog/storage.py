from collections import OrderedDict
import sys

MIB = 1024 * 1024
DEFAULT_BUFFER_LINES = 20_000
MAX_BUFFER_LINES = 65_535
DEFAULT_EVENT_LIMIT = 100_000
MAX_EVENT_LIMIT = 1_000_000
DEFAULT_MEMORY_MIB = 256
MAX_MEMORY_MIB = 2048
EVENT_BATCH_SIZE = 2000


def bounded_integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be a whole number between {minimum:,} and {maximum:,}.")
    return value


class EventStore:
    def __init__(self, event_limit=DEFAULT_EVENT_LIMIT, memory_mib=DEFAULT_MEMORY_MIB):
        self.event_limit = event_limit
        self.memory_mib = memory_mib
        self.max_bytes = memory_mib * MIB
        self.entries = OrderedDict()
        self.estimated_bytes = 0
        self.evicted = 0

    def __len__(self):
        return len(self.entries)

    def append(self, event):
        size = sys.getsizeof(event) + sum(sys.getsizeof(value) for value in event.values()) + 256
        self.entries[event["sequence"]] = (event, size)
        self.estimated_bytes += size
        while len(self.entries) > self.event_limit or self.estimated_bytes > self.max_bytes:
            _, (_, removed_size) = self.entries.popitem(last=False)
            self.estimated_bytes -= removed_size
            self.evicted += 1

    def clear(self):
        self.entries.clear()
        self.estimated_bytes = self.evicted = 0

    def oldest(self, fallback):
        return next(iter(self.entries), fallback)

    def batch(self, since, latest, limit=EVENT_BATCH_SIZE):
        first = max(since + 1, self.oldest(latest + 1))
        end = min(latest + 1, first + limit)
        return [self.entries[sequence][0] for sequence in range(first, end)]

    def snapshot(self):
        return {"event_limit": self.event_limit, "memory_mib": self.memory_mib,
                "estimated_bytes": self.estimated_bytes, "evicted": self.evicted}
