import unittest

from trafficlog.storage import EventStore, MIB, MAX_EVENT_LIMIT


class StorageTests(unittest.TestCase):
    def test_retains_more_than_ten_thousand_and_evicts_oldest(self):
        store = EventStore(15_000, 32)
        for sequence in range(1, 20_001):
            store.append({"sequence": sequence, "source": "192.0.2.1"})
        self.assertEqual(len(store), 15_000)
        self.assertEqual(store.oldest(0), 5001)
        self.assertEqual(store.evicted, 5000)
        cursor, received = 0, []
        while cursor < 20_000:
            batch = store.batch(cursor, 20_000)
            self.assertLessEqual(len(batch), 2000)
            received.extend(event["sequence"] for event in batch)
            cursor = batch[-1]["sequence"]
        self.assertEqual(received, list(range(5001, 20_001)))
        self.assertEqual(store.batch(cursor, 20_000), [])

    def test_memory_budget_applies_even_with_a_million_event_limit(self):
        store = EventStore(MAX_EVENT_LIMIT, 16)
        for sequence in range(1, 301):
            store.append({"sequence": sequence, "raw": str(sequence) + "x" * 100_000})
        self.assertLessEqual(store.estimated_bytes, 16 * MIB)
        self.assertLess(len(store), 300)
        self.assertEqual(store.batch(299, 300)[0]["sequence"], 300)
        self.assertEqual(store.evicted, 300 - len(store))

    def test_oversized_event_and_clear_release_history(self):
        store = EventStore(100, 16)
        store.append({"sequence": 1, "raw": "x" * (17 * MIB)})
        self.assertEqual(len(store), 0)
        self.assertEqual(store.estimated_bytes, 0)
        self.assertEqual(store.batch(0, 1), [])
        store.append({"sequence": 2})
        store.clear()
        self.assertEqual(store.snapshot()["evicted"], 0)
        self.assertEqual(store.estimated_bytes, 0)
        self.assertEqual(store.oldest(3), 3)
