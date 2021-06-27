import os
import pathlib
import sys
import time
from select import select

import click
import gnupg
import pyotp
import pyperclip
import yaml
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.validation import Validator, ValidationError

# Debug only

# Need a MSVcrt for windows
if os.name == "nt":
    import msvcrt

base_dir = os.path.expanduser("~/.vault")


def get_key_list():
    gpg = gnupg.GPG()
    keys = gpg.list_keys(True)
    options = []
    for key in keys:
        id = key["keyid"]
        uids = " ".join(key["uids"])
        options.append(f"{id}: {uids}")
    return options


def find_key_by_name(name):
    gpg = gnupg.GPG()
    keys = gpg.list_keys(True)
    for key in keys:
        if key["keyid"] == name:
            return key

        for id in key["uids"]:
            if name in id:
                return key


def get_secret_names(include_directories=False):
    list = []
    for r, d, f in os.walk(base_dir):
        if include_directories:
            fd = r[len(base_dir) + 1:]
            list.append(fd + os.sep)

        for file in f:
            if not file.endswith(".gpg"):
                continue

            ff = os.path.join(r, file)
            fd = ff[len(base_dir) + 1:-4]
            list.append(fd)

    return list


def read_config():
    config_file = os.path.join(base_dir, "config.yml")
    if not os.path.exists(config_file):
        return None

    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
    return config


def try_read_config():
    config = read_config()
    if config is None:
        sys.stderr.write("Vault is not initialized.  Try vault init")
        sys.exit(-1)


def decrypt(name):
    infile = check_file(name) + ".gpg"

    if not os.path.exists(infile):
        print(f"The no secret named '{name}' exists.")
        sys.exit(-1)

    with open(infile, "r") as f:
        data = f.read()
    gpg = gnupg.GPG()

    return gpg.decrypt(data)


def kb_timout_hit(timeout):
    if os.name == "nt":
        startTime = time.time()
        while True:
            if msvcrt.kbhit():
                inp = msvcrt.getch()
                break
            elif time.time() - startTime > timeout:
                break
    else:
        rlist, wlist, xlist = select([sys.stdin], [], [], timeout)


class ExistsInList(Validator):
    def __init__(self, items):
        self.items = items

    def validate(self, document):
        if not document.text in self.items:
            raise ValidationError(message=f"Secret {document.text} does not exist.")


def prompt_name(must_exist=False):
    include_directories = not must_exist
    secrets = get_secret_names(include_directories)
    if must_exist and not secrets:
        print("There are no secrets to list.  Try adding some.")
        sys.exit(-1)
    secret_completer = WordCompleter(secrets, sentence=True, match_middle=True)
    validator = None
    if must_exist:
        validator = ExistsInList(secrets)

    name = prompt("Name: ", validator=validator, completer=secret_completer)
    return name


def check_file(path):
    path = os.path.join(base_dir, path)
    base_path = pathlib.Path(base_dir).resolve()
    resolved = pathlib.Path(path).resolve()
    if base_path not in (resolved, *resolved.parents):
        print("Tricky path detected.")
        sys.exit(-1)
    return str(resolved)


def prompt_key():
    gpg_keys = get_key_list()
    secret_completer = WordCompleter(gpg_keys, sentence=True, match_middle=True)
    validator = ExistsInList(gpg_keys)

    name = prompt("GPG Key: ", validator=validator, completer=secret_completer)
    id, _ = name.split(":", 2)
    return id


def is_otp_url(key: str):
    return key.startswith("otpauth://")


def totp(url: str):
    otp = pyotp.parse_uri(url.strip())
    return otp.now()


def write_encrypted(name, data):
    config = read_config()
    outfile = check_file(name) + ".gpg"

    gpg = gnupg.GPG()
    key = config["keyid"]
    data = gpg.encrypt(data.encode("utf-8"), key)

    data_path = os.path.dirname(outfile)
    if not os.path.exists(data_path):
        pathlib.Path(data_path).mkdir(parents=True)

    with open(outfile, "w") as of:
        of.write(str(data))


class AliasedGroup(click.Group):

    def get_command(self, ctx, cmd_name):
        print(f"resolving {cmd_name}")
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
def cli():
    pass


@cli.command()
@alias("i")
@click.argument("keyname", required=False)
def init(keyname=None):
    """ initialize a new vault. """
    config_dir = base_dir
    config_file = os.path.join(config_dir, "config.yml")

    if os.path.exists(config_file):
        print("A config file already exists.")
        sys.exit(-1)

    if keyname is None:
        keyname = prompt_key()

    config = {}

    key = find_key_by_name(keyname)
    if not key:
        print("Key not found.")
        sys.exit(-1)

    print(f'Using key {key["keyid"]} ')
    config["keyid"] = key["keyid"]

    if not os.path.isdir(base_dir):
        os.mkdir(base_dir)

    with open(config_file, "w") as f:
        yaml.dump(config, f)

    print("Vault initialized.")


@cli.command()
@alias("a")
@click.argument("name", required=False)
def add(name=None):
    """ Add a secret to the vault. """
    try_read_config()
    if name is None:
        name = prompt_name()

    outfile = check_file(name) + ".gpg"

    pass1 = prompt("Password:", is_password=True)
    pass2 = prompt("Verify:", is_password=True)

    if pass1 != pass2:
        print("Passwords do not match.")
        sys.exit(-1)

    write_encrypted(name, pass1)


@cli.command()
@alias("e")
@click.argument("name", required=False)
def edit(name=None):
    """ create or edit a new multi-line secret. """

    try_read_config()
    if name is None:
        name = prompt_name()
    dest_file = check_file(name) + ".gpg"

    default = ""
    if os.path.exists(dest_file):
        default = str(decrypt(name))

    print("Multiline editor - press M-Enter (or escapt then enter) when done.")
    edited = prompt(default=default, multiline=True)

    write_encrypted(name, edited)


@cli.command()
@click.argument("name", required=False)
@alias("s")
def show(name=None):
    try_read_config()
    if name is None:
        name = prompt_name(True)

    decrypted = str(decrypt(name))

    # If it's an OTP url, return the token instead
    # of the data.
    if is_otp_url(decrypted):
        decrypted = totp(decrypted)

    print(decrypted)


@cli.command(name="list")
@alias("ls", alt="list")
def do_list():
    try_read_config()
    secret_list = get_secret_names()
    for s in secret_list:
        print(s)


@cli.command(name="import")
@alias("i")
@click.argument("name", required=True)
def do_import(name=None):
    try_read_config()

    if name is None:
        name = prompt_name()

    data = sys.stdin.read()
    write_encrypted(name, data)


@cli.command(name="otp")
def import_otp():
    try_read_config()

    for data in sys.stdin.readlines():
        data = data.strip()
        otp = pyotp.parse_uri(data)
        if otp.issuer is not None:
            name = os.path.join("otp", otp.issuer, otp.name)
        else:
            name = os.path.join("otp", otp.name)
        write_encrypted(name, data)


@cli.command()
@click.argument("name", required=False)
def clip(name=None):
    try_read_config()
    if name is None:
        name = prompt_name(True)
    decrypted = str(decrypt(name))

    # If it's an OTP url, return the token instead
    # of the data.
    if is_otp_url(decrypted):
        decrypted = totp(decrypted)

    pyperclip.copy(decrypted)
    print("Password copied to clipboard - this will clear in 20 seconds or if you press a key.")
    timeout = 20
    kb_timout_hit(timeout)
    pyperclip.copy("")


@cli.command()
@click.argument("name", required=False)
def remove(name=None):
    """ remove a secret from the vault. """
    config = try_read_config()


if __name__ == "__main__":
    read_config()
    cli()
