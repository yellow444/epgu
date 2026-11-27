# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Высокоуровневые сценарии поверх :class:`~epgu.client.EpguClient`.

Здесь собран типовой жизненный цикл подачи заявления, чтобы прикладной код
не повторял одну и ту же последовательность «создать заявление затем собрать архив ->
загрузить затем дождаться статуса».
"""

from . import fssp, goskey
from .submit import GoskeySubmitResult, SubmitResult, submit_application, submit_goskey

__all__ = [
    "fssp",
    "goskey",
    "submit_application",
    "submit_goskey",
    "SubmitResult",
    "GoskeySubmitResult",
]
