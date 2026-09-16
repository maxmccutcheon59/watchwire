"""Entropy helper tests — including known FP classes."""

from watchwire.entropy import is_known_fp_token, looks_high_entropy, shannon_entropy


def test_empty_entropy() -> None:
    assert shannon_entropy("") == 0.0


def test_uniform_string_higher_than_repeated() -> None:
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < shannon_entropy("aB3xY9qLmN2pQrStUvWx")


def test_looks_high_entropy() -> None:
    assert looks_high_entropy("a6WBoYYURnraKHMRdzitCdFb/XXihVN1pCm87y4a")
    assert not looks_high_entropy("short")
    assert not looks_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaa")


def test_uuid_is_fp() -> None:
    assert is_known_fp_token("550e8400-e29b-41d4-a716-446655440000")
    assert not looks_high_entropy("550e8400-e29b-41d4-a716-446655440000")
    assert is_known_fp_token("550e8400e29b41d4a716446655440000")


def test_hex_hashes_are_fp() -> None:
    sha1 = "deadbeefcafebabe0123456789abcdef01234567"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert is_known_fp_token(sha1)
    assert is_known_fp_token(sha256)
    assert is_known_fp_token(md5)
    assert not looks_high_entropy(sha1)
    assert not looks_high_entropy(sha256)


def test_base64_padding_noise_is_fp() -> None:
    assert is_known_fp_token("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")
    assert not looks_high_entropy("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")


def test_real_secretish_base64_still_flags() -> None:
    # Same shape as scan fixture / entropy demo — mixed alphabet, not a hash.
    token = "Qk9GVVNBRkFLRUVYQU1QTEVTRUNSRVQwMTIzNDU2Nzg5YWJjZGVm"
    assert not is_known_fp_token(token)
    assert looks_high_entropy(token)
