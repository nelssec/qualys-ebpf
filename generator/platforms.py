"""Qualys Platform Configuration.

Reference: https://www.qualys.com/platform-identification

Each platform has specific gateway URLs for different API types.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class QualysPlatform:
    """Qualys platform configuration."""
    name: str
    pod_id: str
    gateway_url: str
    api_url: str
    portal_url: str
    region: str


# All Qualys platforms with their URLs
PLATFORMS = {
    # United States
    "US1": QualysPlatform(
        name="US Platform 1",
        pod_id="US1",
        gateway_url="gateway.qg1.apps.qualys.com",
        api_url="qualysapi.qualys.com",
        portal_url="qualysguard.qualys.com",
        region="United States",
    ),
    "US2": QualysPlatform(
        name="US Platform 2",
        pod_id="US2",
        gateway_url="gateway.qg2.apps.qualys.com",
        api_url="qualysapi.qg2.apps.qualys.com",
        portal_url="qualysguard.qg2.apps.qualys.com",
        region="United States",
    ),
    "US3": QualysPlatform(
        name="US Platform 3",
        pod_id="US3",
        gateway_url="gateway.qg3.apps.qualys.com",
        api_url="qualysapi.qg3.apps.qualys.com",
        portal_url="qualysguard.qg3.apps.qualys.com",
        region="United States",
    ),
    "US4": QualysPlatform(
        name="US Platform 4",
        pod_id="US4",
        gateway_url="gateway.qg4.apps.qualys.com",
        api_url="qualysapi.qg4.apps.qualys.com",
        portal_url="qualysguard.qg4.apps.qualys.com",
        region="United States",
    ),

    # Europe
    "EU1": QualysPlatform(
        name="EU Platform 1",
        pod_id="EU1",
        gateway_url="gateway.qg1.apps.qualys.eu",
        api_url="qualysapi.qualys.eu",
        portal_url="qualysguard.qualys.eu",
        region="Europe",
    ),
    "EU2": QualysPlatform(
        name="EU Platform 2",
        pod_id="EU2",
        gateway_url="gateway.qg2.apps.qualys.eu",
        api_url="qualysapi.qg2.apps.qualys.eu",
        portal_url="qualysguard.qg2.apps.qualys.eu",
        region="Europe",
    ),
    "EU3": QualysPlatform(
        name="EU Platform 3 (Italy)",
        pod_id="EU3",
        gateway_url="gateway.qg3.apps.qualys.it",
        api_url="qualysapi.qg3.apps.qualys.it",
        portal_url="qualysguard.qg3.apps.qualys.it",
        region="Europe (Italy)",
    ),

    # Canada
    "CA1": QualysPlatform(
        name="Canada Platform 1",
        pod_id="CA1",
        gateway_url="gateway.qg1.apps.qualys.ca",
        api_url="qualysapi.qg1.apps.qualys.ca",
        portal_url="qualysguard.qg1.apps.qualys.ca",
        region="Canada",
    ),

    # India
    "IN1": QualysPlatform(
        name="India Platform 1",
        pod_id="IN1",
        gateway_url="gateway.qg1.apps.qualys.in",
        api_url="qualysapi.qg1.apps.qualys.in",
        portal_url="qualysguard.qg1.apps.qualys.in",
        region="India",
    ),

    # UAE
    "AE1": QualysPlatform(
        name="UAE Platform 1",
        pod_id="AE1",
        gateway_url="gateway.qg1.apps.qualys.ae",
        api_url="qualysapi.qg1.apps.qualys.ae",
        portal_url="qualysguard.qg1.apps.qualys.ae",
        region="United Arab Emirates",
    ),

    # UK
    "UK1": QualysPlatform(
        name="UK Platform 1",
        pod_id="UK1",
        gateway_url="gateway.qg1.apps.qualys.co.uk",
        api_url="qualysapi.qg1.apps.qualys.co.uk",
        portal_url="qualysguard.qg1.apps.qualys.co.uk",
        region="United Kingdom",
    ),

    # Australia
    "AU1": QualysPlatform(
        name="Australia Platform 1",
        pod_id="AU1",
        gateway_url="gateway.qg1.apps.qualys.com.au",
        api_url="qualysapi.qg1.apps.qualys.com.au",
        portal_url="qualysguard.qg1.apps.qualys.com.au",
        region="Australia",
    ),

    # Saudi Arabia
    "KSA1": QualysPlatform(
        name="KSA Platform 1",
        pod_id="KSA1",
        gateway_url="gateway.qg1.apps.qualysksa.com",
        api_url="qualysapi.qg1.apps.qualysksa.com",
        portal_url="qualysguard.qg1.apps.qualysksa.com",
        region="Saudi Arabia",
    ),
}

# Aliases for convenience
PLATFORM_ALIASES = {
    # Short aliases
    "us": "US1",
    "us1": "US1",
    "us01": "US1",
    "us2": "US2",
    "us02": "US2",
    "us3": "US3",
    "us03": "US3",
    "us4": "US4",
    "us04": "US4",
    "eu": "EU1",
    "eu1": "EU1",
    "eu01": "EU1",
    "eu2": "EU2",
    "eu02": "EU2",
    "eu3": "EU3",
    "eu03": "EU3",
    "ca": "CA1",
    "ca1": "CA1",
    "canada": "CA1",
    "in": "IN1",
    "in1": "IN1",
    "india": "IN1",
    "ae": "AE1",
    "ae1": "AE1",
    "uae": "AE1",
    "uk": "UK1",
    "uk1": "UK1",
    "au": "AU1",
    "au1": "AU1",
    "australia": "AU1",
    "ksa": "KSA1",
    "ksa1": "KSA1",
    "saudi": "KSA1",
}


def get_platform(pod_id: str) -> Optional[QualysPlatform]:
    """Get platform configuration by pod ID or alias.

    Args:
        pod_id: Platform identifier (e.g., "US2", "CA1", "eu", "canada")

    Returns:
        QualysPlatform configuration or None if not found
    """
    # Normalize input
    pod_id_lower = pod_id.lower().strip()
    pod_id_upper = pod_id.upper().strip()

    # Check aliases first
    if pod_id_lower in PLATFORM_ALIASES:
        pod_id_upper = PLATFORM_ALIASES[pod_id_lower]

    return PLATFORMS.get(pod_id_upper)


def list_platforms() -> None:
    """Print all available platforms."""
    print("Available Qualys Platforms:")
    print("-" * 70)
    print(f"{'Pod ID':<8} {'Name':<25} {'Gateway URL':<35}")
    print("-" * 70)

    for pod_id, platform in sorted(PLATFORMS.items()):
        print(f"{pod_id:<8} {platform.name:<25} {platform.gateway_url:<35}")

    print("")
    print("Aliases: us, us2, ca, canada, eu, eu2, india, uae, uk, australia, ksa")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        pod = sys.argv[1]
        platform = get_platform(pod)
        if platform:
            print(f"Platform: {platform.name}")
            print(f"Pod ID: {platform.pod_id}")
            print(f"Gateway: {platform.gateway_url}")
            print(f"API: {platform.api_url}")
            print(f"Portal: {platform.portal_url}")
        else:
            print(f"Unknown platform: {pod}")
            list_platforms()
    else:
        list_platforms()
