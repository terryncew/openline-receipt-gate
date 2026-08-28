"""Paper-spec arms for SARA-SPEC-001."""

from .broad_recall import evaluate_broad_recall
from .minimal_sara import evaluate_minimal_sara
from .openline_recall import evaluate_openline_recall
from .published_sara import evaluate_published_sara

__all__ = [
    "evaluate_broad_recall",
    "evaluate_minimal_sara",
    "evaluate_openline_recall",
    "evaluate_published_sara",
]
