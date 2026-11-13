"""XSSentinel package root."""
from .core.scanner import Scanner, Finding
from .core.requester import Requester

__version__ = "2.0.1"
__all__ = ["Scanner", "Requester", "Finding"]
