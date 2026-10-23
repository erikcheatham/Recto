"""The shard selection CI uses (tests/conftest.py select_shard): the shards of one total partition the suite."""

from __future__ import annotations

import pytest

from tests.conftest import select_shard


@pytest.mark.parametrize("total", [1, 2, 3, 4, 7])
@pytest.mark.parametrize("count", [0, 1, 4, 23])
def test_the_shards_of_one_total_partition_the_items(total: int, count: int) -> None:
    items = list(range(count))
    seen: list[int] = []
    for index in range(1, total + 1):
        kept, deselected = select_shard(items, f"{index}/{total}")
        assert sorted(kept + deselected) == items
        seen.extend(kept)
    assert sorted(seen) == items
    assert len(seen) == len(set(seen))


def test_items_are_dealt_out_in_turn() -> None:
    kept, _ = select_shard(list(range(10)), "2/4")
    assert kept == [1, 5, 9]


@pytest.mark.parametrize("spec", ["", "4", "0/4", "5/4", "1/0", "a/b", "1/4/2", "-1/4", "1.0/4"])
def test_a_malformed_spec_is_refused(spec: str) -> None:
    with pytest.raises(ValueError):
        select_shard([1, 2, 3], spec)
