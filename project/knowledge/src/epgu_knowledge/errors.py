"""Ошибки пакета знаний."""
from __future__ import annotations


class KnowledgeError(Exception):
    """Базовая ошибка: машинный код и человекочитаемое сообщение."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class NotFound(KnowledgeError):
    """Запрошенный маршрут, узел или источник не существует."""

    def __init__(self, message: str) -> None:
        super().__init__("not_found", message)


class InvalidDataset(KnowledgeError):
    """Набор знаний не прошёл проверку схемы или ссылочной целостности.

    ``errors`` содержит первые замечания (без локальных путей), ``total`` их число.
    """

    def __init__(self, code: str, errors: list, *, total: int) -> None:
        super().__init__(code, f"набор знаний не прошёл проверку: {total} замечаний")
        self.errors = list(errors)
        self.total = total
