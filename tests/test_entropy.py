"""Entropy helper tests."""

from watchwire.entropy import looks_high_entropy, shannon_entropy


def test_empty_entropy() -> None:
    assert shannon_entropy("") == 0.0


def test_uniform_string_higher_than_repeated() -> None:
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < shannon_entropy("aB3xY9qLmN2pQrStUvWx")


def test_looks_high_entropy() -> None:
    assert looks_high_entropy("a6WBoYYURnraKHMRdzitCdFb/XXihVN1pCm87y4a")
    assert not looks_high_entropy("short")
    assert not looks_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaa")
