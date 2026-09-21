"""Contract tests for the SecretSource ABC and the SecretMaterial sealed type.

These tests pin the public API shape that all secret-source backends must
honor. Adding a new backend should NOT change anything in this file.
"""

from __future__ import annotations

from typing import Any

import pytest

from recto.secrets.base import (
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SecretSourceError,
    SigningCapability,
)


class TestDirectSecret:
    def test_value_accessible(self) -> None:
        s = DirectSecret(value="hunter2")
        assert s.value == "hunter2"

    def test_repr_redacted(self) -> None:
        s = DirectSecret(value="hunter2")
        assert "hunter2" not in repr(s)
        assert "redacted" in repr(s)

    def test_str_redacted(self) -> None:
        s = DirectSecret(value="hunter2")
        assert "hunter2" not in str(s)
        assert "redacted" in str(s)

    def test_frozen(self) -> None:
        s = DirectSecret(value="hunter2")
        with pytest.raises((AttributeError, TypeError)):
            s.value = "rotated"  # type: ignore[misc]

    def test_format_does_not_leak(self) -> None:
        # f-strings call __format__ which falls back to __str__.
        s = DirectSecret(value="hunter2")
        formatted = f"{s}"
        assert "hunter2" not in formatted


class TestSigningCapability:
    def test_repr_redacted(self) -> None:
        s = SigningCapability(
            sign=lambda b: b"sig",
            public_key=b"pk",
            algorithm="ed25519",
        )
        rendered = repr(s)
        assert "redacted" in rendered
        assert "ed25519" in rendered  # algorithm name is non-secret debug info

    def test_str_redacted(self) -> None:
        s = SigningCapability(
            sign=lambda b: b"sig",
            public_key=b"pk",
            algorithm="ed25519",
        )
        rendered = str(s)
        assert "redacted" in rendered

    def test_frozen(self) -> None:
        s = SigningCapability(
            sign=lambda b: b"sig",
            public_key=b"pk",
            algorithm="ed25519",
        )
        with pytest.raises((AttributeError, TypeError)):
            s.algorithm = "ecdsa-p256"  # type: ignore[misc]


class TestSecretMaterialUnion:
    """SecretMaterial is the sum type that fetch() returns. Both variants
    must be accepted by isinstance checks and by callers using match
    statements."""

    def test_direct_is_secret_material(self) -> None:
        s: SecretMaterial = DirectSecret(value="x")
        assert isinstance(s, DirectSecret)

    def test_signing_is_secret_material(self) -> None:
        s: SecretMaterial = SigningCapability(
            sign=lambda b: b"sig",
            public_key=b"pk",
            algorithm="ed25519",
        )
        assert isinstance(s, SigningCapability)


class TestSecretSourceABC:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            SecretSource()  # type: ignore[abstract]

    def test_concrete_subclass_must_implement_fetch_and_name(self) -> None:
        class Incomplete(SecretSource):
            @property
            def name(self) -> str:
                return "incomplete"
            # missing fetch

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_minimal_concrete_subclass_works(self) -> None:
        class Minimal(SecretSource):
            @property
            def name(self) -> str:
                return "minimal"

            def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
                return DirectSecret(value=f"{secret_name}-value")

        s = Minimal()
        assert s.name == "minimal"
        result = s.fetch("foo", {})
        assert isinstance(result, DirectSecret)
        assert result.value == "foo-value"
        # Default lifecycle / rotation behavior:
        assert s.supports_lifecycle() is False
        assert s.supports_rotation() is False
        with pytest.raises(NotImplementedError):
            s.rotate("foo", "new-value")


class TestExceptionHierarchy:
    def test_not_found_is_source_error(self) -> None:
        # SecretNotFoundError must be catchable as SecretSourceError so
        # callers can choose to handle either case uniformly.
        assert issubclass(SecretNotFoundError, SecretSourceError)
