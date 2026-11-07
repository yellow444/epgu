"""Справочная база знаний по подключению к API Госуслуг (только чтение)."""
from . import limits
from .base import KnowledgeBase, load
from .connection_card import (
    ConnectionCard, connection_card_input_schema, connection_card_output_schema,
    connection_card_schema, load_connection_card,
)
from .errors import InvalidDataset, KnowledgeError, NotFound
from .manual_path import ManualPath, load_manual_path, manual_path_schema

__all__ = [
    "load", "KnowledgeBase", "KnowledgeError", "InvalidDataset", "NotFound", "limits",
    "ManualPath", "load_manual_path", "manual_path_schema",
    "ConnectionCard", "connection_card_input_schema", "connection_card_output_schema",
    "connection_card_schema", "load_connection_card",
]
__version__ = "0.1.0"
