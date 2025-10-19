"""RFC3339 timestamp formatting with millisecond precision.

This module provides RFC3339 timestamp formatting with millisecond precision (3 digits).
"""

import re
from datetime import datetime, timezone

from better_auth.interfaces.encoding import ITimestamper


class Rfc3339Nano(ITimestamper):
    """RFC3339 timestamp formatter with millisecond precision.

    This class formats datetime objects to RFC3339 strings with millisecond
    precision (3 digits). Python's datetime.isoformat() provides microsecond precision
    (6 digits), so this implementation truncates to milliseconds (3 digits).
    """

    def format(self, when: datetime) -> str:
        """Format a datetime object as an RFC3339 string with millisecond precision.

        Converts a datetime to ISO format and truncates microseconds (6 digits) to
        milliseconds (3 digits).

        Args:
            when: The datetime to format.

        Returns:
            The formatted RFC3339 timestamp string with millisecond precision.

        Example:
            >>> from datetime import datetime, timezone
            >>> dt = datetime(2025, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
            >>> Rfc3339Nano().format(dt)
            '2025-01-01T12:00:00.123Z'
        """
        # Convert to UTC if timezone-aware
        if when.tzinfo is not None:
            when = when.astimezone(timezone.utc)
        else:
            # Assume UTC if naive
            when = when.replace(tzinfo=timezone.utc)

        # Get ISO string
        iso_string = when.isoformat()

        # Handle the Z suffix replacement
        # isoformat() gives us something like: 2025-01-01T12:00:00.123456+00:00
        # We need: 2025-01-01T12:00:00.123Z
        if iso_string.endswith("+00:00"):
            iso_string = iso_string[:-6] + "Z"
        elif not iso_string.endswith("Z"):
            # If no timezone info in the string, add Z
            iso_string = iso_string + "Z"

        # Truncate microseconds (6 digits) to milliseconds (3 digits)
        # Match pattern: .XXXXXX where X are digits, keep only first 3
        iso_string = re.sub(r"\.(\d{3})\d{3}Z", r".\1Z", iso_string)

        return iso_string

    def parse(self, when: str | datetime) -> datetime:
        """Parse a timestamp string or datetime into a datetime object.

        If the input is already a datetime, returns it as-is. If it's a string,
        parses it using datetime.fromisoformat() which handles RFC3339 format.

        Args:
            when: The timestamp string or datetime to parse.

        Returns:
            The parsed datetime object.

        Example:
            >>> Rfc3339Nano().parse('2025-01-01T12:00:00.123Z')
            datetime.datetime(2025, 1, 1, 12, 0, 0, 123000, tzinfo=datetime.timezone.utc)
        """
        if isinstance(when, datetime):
            return when

        # Truncate any precision beyond milliseconds for Python parsing
        # Keep only 3 fractional digits
        timestamp_str = re.sub(r"\.(\d{3})\d+Z", r".\1Z", when)

        # Replace 'Z' with '+00:00' for fromisoformat compatibility
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"

        return datetime.fromisoformat(timestamp_str)

    def now(self) -> datetime:
        """Get the current datetime in UTC.

        Returns:
            The current datetime with UTC timezone.

        Example:
            >>> now = Rfc3339Nano().now()
            >>> now.tzinfo == timezone.utc
            True
        """
        return datetime.now(timezone.utc)
