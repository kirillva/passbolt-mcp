"""Shared building blocks for the Passbolt sinks.

Layers:
- ``envelope``  parses the credential envelope and resolves the record target
- ``guards``    decides what is allowed (web steps, read-only SQL, ssh profiles)
- ``executors`` performs the protocol action and makes no policy decisions
- ``cli``       composes the layers and writes a uniform result file
"""

__version__ = "1.0.0"
