"""Локальные операции с учётными записями установки.

Запускаются на машине установки, внутри контейнера API:

    python auth_cli.py create-admin --login admin
    python auth_cli.py reset-password --login admin

Пароль вводится с клавиатуры дважды или одной строкой через stdin с ключом
``--password-stdin``. В аргументах командной строки пароль не принимается:
он остался бы в истории оболочки и в списке процессов.
"""

from __future__ import annotations

import argparse
import getpass
import sys

import auth
import auth_store


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Пароль: ")
    second = getpass.getpass("Повторите пароль: ")
    if first != second:
        raise SystemExit("Пароли не совпали")
    return first


def cmd_create_admin(args) -> int:
    auth_store.initialize_once()
    if auth.has_installation_admin() and not args.additional:
        print(
            "Администратор уже есть. Второго создайте с ключом --additional или в интерфейсе.",
            file=sys.stderr,
        )
        return 2
    password = _read_password(args.password_stdin)
    try:
        account = auth.create_account(
            args.login,
            password,
            display_name=args.display_name,
            installation_admin=True,
            source="cli",
        )
    except auth.AuthError as err:
        print(str(err), file=sys.stderr)
        return 2
    print("Создан администратор %s (%s)" % (account.login, account.id))
    return 0


def cmd_reset_password(args) -> int:
    password = _read_password(args.password_stdin)
    try:
        auth.set_password_locally(args.login, password)
    except auth.AuthError as err:
        print(str(err), file=sys.stderr)
        return 2
    print("Пароль %s изменён, все его сессии завершены" % args.login)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Учётные записи установки")
    commands = parser.add_subparsers(dest="command", required=True)

    admin = commands.add_parser("create-admin", help="создать администратора установки")
    admin.add_argument("--login", required=True)
    admin.add_argument("--display-name", default="")
    admin.add_argument("--password-stdin", action="store_true")
    admin.add_argument("--additional", action="store_true")
    admin.set_defaults(handler=cmd_create_admin)

    reset = commands.add_parser("reset-password", help="сменить пароль с консоли")
    reset.add_argument("--login", required=True)
    reset.add_argument("--password-stdin", action="store_true")
    reset.set_defaults(handler=cmd_reset_password)

    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
