"""Regression tests for the CA bundle shipped with pip's vendored certifi.

CVE-2026-133949: roots that Mozilla distrusted must no longer be trusted by
pip's default CA bundle.
"""

from __future__ import annotations

import hashlib
import os
import re
import ssl
from collections.abc import Callable

import pytest

from pip._vendor import certifi

# SHA-256 fingerprints (DER) of roots removed from the Mozilla trust store.
DISTRUSTED_ROOTS = {
    # Atos TrustedRoot 2011
    "f356bea244b7a91eb35d53ca9ad7864ace018e2d35d5f8f96ddf68a6f41aa474",
    # emSign ECC Root CA - G3
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
}

# SHA-256 fingerprints (DER) of roots added in certifi 2026.10.19.
ADDED_ROOTS = {
    "1435f225c5d252d7a21948cc3ce62aecfa88001e3dd72d1cc3555100eb372f93",
    "6ab2ab75f51cb4f4f0156203fbf6f646232f514be059f62833308b82b4d72db1",
    "098e08a91dbbf77478b96cceb89b1413a5da37b7c862606a955deb07179f4326",
    "d13db1294c45ebc6fc86c6bbf69fa29bdfe692dff7c713c243c7a956c6a2284c",
}

_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)


def _bundle_fingerprints() -> set[str]:
    with open(certifi.where(), encoding="ascii") as f:
        pem_blocks = _PEM_RE.findall(f.read())
    return {
        hashlib.sha256(ssl.PEM_cert_to_DER_cert(block)).hexdigest()
        for block in pem_blocks
    }


def _ssl_context_fingerprints() -> set[str]:
    context = ssl.create_default_context(cafile=certifi.where())
    return {
        hashlib.sha256(der).hexdigest()
        for der in context.get_ca_certs(binary_form=True)
    }


def test_bundle_exists() -> None:
    assert os.path.isfile(certifi.where())


def test_bundle_loads_into_ssl_context() -> None:
    fingerprints = _ssl_context_fingerprints()
    assert len(fingerprints) > 100


@pytest.mark.parametrize(
    "get_fingerprints", [_bundle_fingerprints, _ssl_context_fingerprints]
)
def test_distrusted_roots_are_not_trusted(
    get_fingerprints: Callable[[], set[str]],
) -> None:
    fingerprints = get_fingerprints()
    assert fingerprints, "no certificates found in the vendored CA bundle"
    assert DISTRUSTED_ROOTS.isdisjoint(fingerprints)


@pytest.mark.parametrize(
    "get_fingerprints", [_bundle_fingerprints, _ssl_context_fingerprints]
)
def test_added_roots_are_trusted(get_fingerprints: Callable[[], set[str]]) -> None:
    assert ADDED_ROOTS <= get_fingerprints()
