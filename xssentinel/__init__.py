"""XSSentinel package root."""
from .core.scanner import Scanner, Finding
from .core.requester import Requester

__version__ = "1.2.2"
__all__ = ["Scanner", "Requester", "Finding"]
