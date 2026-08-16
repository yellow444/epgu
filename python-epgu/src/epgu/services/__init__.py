# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Высокоуровневые сценарии поверх :class:`~epgu.client.EpguClient`.

Здесь собран типовой жизненный цикл подачи заявления, чтобы прикладной код
не повторял одну и ту же последовательность «создать заявление -> собрать архив ->
загрузить -> дождаться статуса».
"""

from . import goskey
from .submit import GoskeySubmitResult, SubmitResult, submit_application, submit_goskey

__all__ = [
    "goskey",
    "submit_application",
    "submit_goskey",
    "SubmitResult",
    "GoskeySubmitResult",
]
