"""Высокоуровневые сценарии поверх :class:`~epgu.client.EpguClient`.

Здесь собран типовой жизненный цикл подачи заявления, чтобы прикладной код
не повторял одну и ту же последовательность «создать заявление -> собрать архив ->
загрузить -> дождаться статуса».
"""

from .submit import SubmitResult, submit_application

__all__ = ["submit_application", "SubmitResult"]
