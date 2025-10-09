"""RFC3339 timestamp formatting with nanosecond precision.

This module provides RFC3339 timestamp formatting that matches the TypeScript
implementation's nanosecond precision format.
"""

from datetime import datetime, timezone

from better_auth.interfaces.encoding import ITimestamper


class Rfc3339Nano(ITimestamper):
    """RFC3339 timestamp formatter with nanosecond precision.

    This class formats datetime objects to RFC3339 strings with nanosecond
    precision. Since Python's datetime.isoformat() provides microsecond precision
    (6 digits), this implementation extends it to nanoseconds (9 digits) by appending
    three zeros (e.g., 2025-01-01T12:00:00.123456000Z).
    """

    def format(self, when: datetime) -> str:
        """Format a datetime object as an RFC3339 string with nanosecond precision.

        Converts a datetime to ISO format and extends microseconds (6 digits) to
        nanoseconds (9 digits) by appending three zeros before the 'Z' timezone indicator.

        Args:
            when: The datetime to format.

        Returns:
            The formatted RFC3339 timestamp string with nanosecond precision.

        Example:
            >>> from datetime import datetime, timezone
            >>> dt = datetime(2025, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
            >>> Rfc3339Nano().format(dt)
            '2025-01-01T12:00:00.123456000Z'
        """
        # Convert to UTC if timezone-aware
        if when.tzinfo is not None:
            when = when.astimezone(timezone.utc)
        else:
            # Assume UTC if naive
            when = when.replace(tzinfo=timezone.utc)

        # Get ISO string and replace 'Z' with '000000Z' to add nanosecond precision
        iso_string = when.isoformat()

        # Handle the Z suffix replacement
        # isoformat() gives us something like: 2025-01-01T12:00:00.123456+00:00
        # We need: 2025-01-01T12:00:00.123456000Z
        if iso_string.endswith("+00:00"):
            iso_string = iso_string[:-6] + "Z"
        elif not iso_string.endswith("Z"):
            # If no timezone info in the string, add Z
            iso_string = iso_string + "Z"

        # Now replace Z with 000Z to extend microseconds (6 digits) to nanoseconds (9 digits)
        return iso_string.replace("Z", "000Z")

    def parse(self, when: str | datetime) -> datetime:
        """Parse a timestamp string or datetime into a datetime object.

        If the input is already a datetime, returns it as-is. If it's a string,
        parses it using datetime.fromisoformat() which handles RFC3339 format.

        Args:
            when: The timestamp string or datetime to parse.

        Returns:
            The parsed datetime object.

        Example:
            >>> Rfc3339Nano().parse('2025-01-01T12:00:00.123456000Z')
            datetime.datetime(2025, 1, 1, 12, 0, 0, 123456, tzinfo=datetime.timezone.utc)
        """
        if isinstance(when, datetime):
            return when

        # Remove nanosecond precision (keep only microseconds) for Python parsing
        # Convert nanoseconds (9 digits) to microseconds (6 digits) by removing the last 3 digits
        timestamp_str = when.replace("000Z", "Z")

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
