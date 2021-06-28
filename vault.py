import os
import sys
import time
from select import select

import click
import gnupg
import pyotp
import pyperclip
import yaml
import re
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.validation import Validator, ValidationError

from tools import find_key_by_name, generate, Vault

# Need a MSVcrt for windows
if os.name == "nt":
    import msvcrt


def get_key_list():
    gpg = gnupg.GPG()
    keys = gpg.list_keys(True)
    options = []
    for key in keys:
        key_id = key["keyid"]
        uids = " ".join(key["uids"])
        options.append(f"{key_id}: {uids}")
    return options


def kb_timout_hit(timeout):
    if os.name == "nt":
        start_time = time.time()
        while True:
            if msvcrt.kbhit():
                _ = msvcrt.getch()
                break
            elif time.time() - start_time > timeout:
                break
    else:
        _, _, _ = select([sys.stdin], [], [], timeout)


class ExistsInList(Validator):
    def __init__(self, items):
        self.items = items

    def validate(self, document):
        if document.text not in self.items:
            raise ValidationError(message=f"Secret {document.text} does not exist.")


def prompt_name(vault: Vault, must_exist=False):
    include_directories = not must_exist
    secrets = vault.list(include_directories)
    if must_exist and not secrets:
        print("There are no secrets to list.  Try adding some.")
        sys.exit(-1)
    secret_completer = WordCompleter(secrets, sentence=True, match_middle=True)
    validator = None
    if must_exist:
        validator = ExistsInList(secrets)

    name = prompt("Name: ", validator=validator, completer=secret_completer)
    return name


def prompt_key():
    gpg_keys = get_key_list()
    secret_completer = WordCompleter(gpg_keys, sentence=True, match_middle=True)
    validator = ExistsInList(gpg_keys)

    name = prompt("GPG Key: ", validator=validator, completer=secret_completer)
    key_id, _ = name.split(":", 2)
    return key_id


def is_otp_url(key: str):
    return key.startswith("otpauth://")


def totp(url: str):
    otp = pyotp.parse_uri(url.strip())
    return otp.now()


class AliasedGroup(click.Group):

    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv

        if cmd_name not in AliasedGroup.aliases:
            return None

        return click.Group.get_command(self, ctx, AliasedGroup.aliases[cmd_name])

    def resolve_command(self, ctx, args):
        # always return the full command name
        _, cmd, args = super().resolve_command(ctx, args)
        return cmd.name, cmd, args


AliasedGroup.aliases = {}


def alias(name, alt=None):
    def do_handle(cb):
        command = alt
        if alt is None:
            command = cb.__name__
        AliasedGroup.aliases[name] = command
        return cb

    return do_handle


@click.group(cls=AliasedGroup)
@click.option("--vault-location", "-l", default=None)
@click.pass_context
def cli(ctx, vault_location=None):
    """cli tool for managing secrets."""

    if vault_location is None:
        vault_location = os.path.expanduser("~/.vault")
    
    ctx.obj["location"] = vault_location

    def get_vault():
        return Vault(base_dir=vault_location)

    ctx.obj.get_vault = get_vault


@cli.command()
@click.argument("key-name", required=False)
@click.pass_context
@alias("i")
def init(ctx, key_name=None):
    """ initialize a new vault. """
    config_dir = ctx.obj.location
    config_file = os.path.join(config_dir, ".config.yml")
    id_file = os.path.join(config_dir, ".gpg-id")

    if os.path.exists(config_file):
        print("A config file already exists.")
        sys.exit(-1)

    if key_name is None:
        key_name = prompt_key()

    config = {}

    key = find_key_by_name(key_name)
    if not key:
        print("Key not found.")
        sys.exit(-1)

    print(f'Using key {key["keyid"]} ')
    config["keyid"] = key["keyid"]

    print(config_dir)
    if not os.path.isdir(config_dir):
        os.mkdir(config_dir)

    with open(config_file, "w") as f:
        yaml.dump(config, f)

    with open(id_file, "w") as f:
        f.write(key["keyid"])

    print("Vault initialized.")


@cli.command()
@click.argument("name", required=False)
@click.pass_context
@alias("a")
def add(ctx, name=None):
    """ Add a secret to the vault. """
    vault = ctx.obj.get_vault()
    if name is None:
        name = prompt_name(vault)

    pass1 = prompt("Password:", is_password=True)
    pass2 = prompt("Verify:", is_password=True)

    if pass1 != pass2:
        print("Passwords do not match.")
        sys.exit(-1)

    vault.write(name, pass1)


@cli.command()
@click.argument("name", required=False)
@click.pass_context
@alias("e")
def edit(ctx, name=None):
    """ create or edit a new multi-line secret. """
    vault = ctx.obj.get_vault()
    if name is None:
        name = prompt_name(vault)

    default = vault.try_decrypt(name)
    default = str(default) if default is not None else ""

    print("Multiline editor - press M-Enter (or escape then enter) when done.")
    edited = prompt(default=default, multiline=True)

    vault.write(name, edited)


@cli.command()
@click.argument("name", required=False)
@click.pass_context
@alias("s")
def show(ctx, name=None):
    """displays the secret on stdout."""
    vault = ctx.obj.get_vault()
    if name is None:
        name = prompt_name(vault, True)

    decrypted = str(vault.decrypt(name))
    # If it's an OTP url, return the token instead
    # of the data.
    if is_otp_url(decrypted):
        decrypted = totp(decrypted)

    print(decrypted)


@cli.command(name="list")
@click.pass_context
@alias("ls", alt="list")
def do_list(ctx):
    """list stored secret names."""
    vault = ctx.obj.get_vault()
    secret_list = vault.list()
    for s in secret_list:
        print(s)


@cli.command(name="import")
@click.pass_context
@click.argument("name", required=True)
@alias("i")
def do_import(ctx, name=None):
    """reads the contents of the secret from stdin."""
    vault = ctx.obj.get_vault()

    if name is None:
        name = prompt_name(vault)

    data = sys.stdin.read()
    vault.write(name, data)


@cli.command(name="otp")
@click.pass_context
def import_otp(ctx):
    """import an OTP secret from stdin."""
    vault = ctx.obj.get_vault()

    for data in sys.stdin.readlines():
        data = data.strip()
        data = re.sub('^QR-Code:', '', data)
        
        otp = pyotp.parse_uri(data)
        if otp.issuer is not None:
            name = os.path.join("otp", otp.issuer, otp.name)
        else:
            name = os.path.join("otp", otp.name)
        vault.write(name, data)


@cli.command()
@click.argument("name", required=False)
@click.option("--duration", "-d", type=click.INT, default=20, required=False)
@click.pass_context
def clip(ctx, name=None, duration=20):
    """copy the secret to the clipboard for a short period of time.

    The --duration option lets you specify a duration the secret will remain on the clipboard.
    Passing a negative or zero duration will leave the secret on the clipboard and exit
    immediately.

    Pressing a key will terminate and clear the secret from the clipboard.
    """
    vault = ctx.obj.get_vault()
    if name is None:
        name = prompt_name(vault, True)
    decrypted = str(vault.decrypt(name))

    # If it's an OTP url, return the token instead
    # of the data.
    if is_otp_url(decrypted):
        decrypted = totp(decrypted)

    pyperclip.copy(decrypted)
    if duration > 0:
        print(f"Password copied to clipboard - this will clear in {duration} seconds or if you press a key.")
        kb_timout_hit(duration)
        pyperclip.copy("")


@cli.command()
@click.argument("name", required=False)
@click.pass_context
@alias("rm")
def remove(ctx, name=None):
    """ remove a secret from the vault. """
    vault = ctx.obj.get_vault()
    if name is None:
        name = prompt_name(vault, True)
    vault.remove(name)


@cli.command(name="generate")
@click.argument("name", required=False)
@click.option("--length", type=click.IntRange(1, 1000), default=15, required=False)
@click.option("--digits", type=click.BOOL, default=True)
@click.option("--lowercase", type=click.BOOL, default=True)
@click.option("--uppercase", type=click.BOOL, default=True)
@click.option("--echo", type=click.BOOL, default=False)
@click.option("--symbols", type=click.BOOL, default=True)
@click.pass_context
@alias("gen", alt="generate")
def do_generate(ctx, name, length=15, digits=True, lowercase=True, uppercase=True, symbols=True, echo=False):
    vault = ctx.obj.get_vault()
    if name is None:
        name = prompt_name(vault, False)
    res = generate(length,
                   digits=digits,
                   lowercase=lowercase,
                   uppercase=uppercase,
                   symbols=symbols)
    vault.write(name, res)
    if echo:
        print(res)


class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == "__main__":
    cli(obj=AttrDict())
    try:
        # cli(obj=AttrDict())
        pass
    except Exception as ex:
        print(ex)
