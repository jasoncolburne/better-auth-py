"""Tests for token parsing functionality."""

from __future__ import annotations

from typing import Any

import pytest

from better_auth.messages.access import AccessToken
from examples.implementation.encoding import TokenEncoder


class MockAccessAttributes:
    """Mock access attributes for testing."""

    def __init__(self, permissions_by_role: dict[str, list[str]] | None = None) -> None:
        """Initialize mock attributes.

        Args:
            permissions_by_role: Dictionary mapping roles to their permissions.
        """
        self.permissions_by_role = permissions_by_role or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of the attributes.
        """
        return {"permissionsByRole": self.permissions_by_role}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MockAccessAttributes:
        """Create instance from dictionary.

        Args:
            data: Dictionary containing attribute data.

        Returns:
            MockAccessAttributes instance.
        """
        return cls(permissions_by_role=data.get("permissionsByRole", {}))


@pytest.mark.asyncio
async def test_token_parsing() -> None:
    """Test that tokens can be parsed correctly."""
    token_encoder = TokenEncoder()

    token_string = "0IAGTf0y29Ra-8cjCnXS8NlImAi4_KZfaxgr_5iAux1CLoOZ7d5tvFktxb8Xc6pU2pYQkMw0V75fwP537N9dToIyH4sIAAAAAAACA22PXY-iMBSG_wvX203rUBHuOgIDasQ1jC5uNobaKkU-TFtAZ-J_nzoXu8nOnsuT93k_3i3FZc9lzHijhb5ZnoUIiUl_mNkp0isAWHpgCzKMWSaghJvE309VxifT6_no3Nh1G1jfLMZ7ceCGDYJhvIoDqXySVCAcPdfc2VFYlHG-TabDa0leu1NE56Byc8OJv6lB0taqqFx5jGadHfUiTU9OHYrFXp17FmKIdpfMZk80ileGvHS0Eoc5_1P4jVIM1qW92Qb-7keC6-HlxZH-Yjm-Coxilm1Q2-AV3dPO4LLVuRZtE-WqeISHIZDEGWe125Z-BnVHxc9NuQZk3c-XziyS5-2ybt6OpyJ51Faq44xoQ47gCAMEAZykaORh17PR9wnG8PN2RsuvFyFv_yifPGR_UUp-lFwVwRfATSH8n3WutRS001xZ3rt14bI2xcwo9XxbtxV_PHNWi8byfhnznBlkkEJz6_f9fv8A44o2TvkBAAA"

    token = await AccessToken.parse(token_string, token_encoder)

    assert token.server_identity == "1AAIAvcJ4T1tP--dTcdLAw6dYi0r0VOD_CsYe8Cxkf7ydxWE"
    assert token.device == "EEw6PIErsDAOl-F2Bme7Zb0hjIaWOCwUjAUugHbK-l9a"
    assert token.identity == "EOomshl9rfHJu4HviTTg7mFiL_skvdF501ZpY4d3bHIP"
    assert token.public_key == "1AAIAzbb5-Rj4VWEDZQO5mwGG7rDLN6xi51IdYV1on5Pb_bu"
    assert token.rotation_hash == "EFF-rA76Ym9ojDY0tubiXVjR-ARvKN7JHrkWNmnzfghO"
    assert token.issued_at == "2025-10-08T12:59:41.855000000Z"
    assert token.expiry == "2025-10-08T13:14:41.855000000Z"
    assert token.refresh_expiry == "2025-10-09T00:59:41.855000000Z"
    assert token.attributes == {"permissionsByRole": {"admin": ["read", "write"]}}
