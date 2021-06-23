#!/usr/bin/env python3
import gnupg
import os
import time
import yaml
import sys
import pathlib
import string
import secrets
import subprocess
import pyotp
import pyperclip
from select import select
from pathlib import Path
from itertools import islice
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.validation import Validator, ValidationError

# Debug only
from icecream import ic

# Need a MSVcrt for windows
if os.name == "nt":
    import msvcrt

base_dir = os.path.expanduser("~/.vault")
command_handlers = {}

usage_str = """
vault <command>

    init <gpgkey>   - initilizes the vault store and uses the specified gpg key
                      for encryption.
    add|a <name>    - adds a new password (prompts for password).
    list|ls         - lists stored password names.
    edit|e <name>   - multi-line editor for adding/editing multi-line secrets.
    show|s <name>   - displays on output.
    clip|c <name>   - copies the named secret to the clipboard.
    help|h          - displays this message.

"""

def handles(*args):
    def do_handle(cb):
        for name in args:
            command_handlers[name] = cb
        return cb

    return do_handle


def list_keys():
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
    global config
    config_file = os.path.join(base_dir, "config.yml")
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)


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
            raise ValidationError(message = f"Secret {document.text} does not exist.")

def prompt_name(must_exist=False):
    include_directories = not must_exist
    secrets = get_secret_names(include_directories)
    if must_exist and not secrets:
        print("There are no secrets to list.  Try adding some.")
        sys.exit(-1)
    secret_completer  = WordCompleter(secrets, sentence=True, match_middle=True)
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
    gpg_keys = list_keys()
    secret_completer  = WordCompleter(gpg_keys, sentence=True, match_middle=True)
    validator = ExistsInList(gpg_keys)

    name = prompt("GPG Key: ", validator=validator, completer=secret_completer)
    id, _ = name.split(":", 2)
    return id

def is_otp_url(key: str):
    return key.startswith("otpauth://")

def totp(url: str):
    otp = pyotp.parse_uri(url.strip())
    return otp.now()


@handles("init", "i")
def init(keyname=None):
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


@handles("clip", "c")
def clip(name=None):
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


@handles("edit", "e")
def edit(name = None):
    if name is None:
        name = prompt_name()
    dest_file = check_file(name) + ".gpg"

    default = ""
    if os.path.exists(dest_file):
        default = str(decrypt(name))


    print("Multiline editor - press M-Enter (or escapt then enter) when done.")
    edited = prompt(default=default, multiline=True)

    write_encrypted(name, edited)
    """
    gpg = gnupg.GPG()
    key = config["keyid"]
    data = gpg.encrypt(edited.encode("utf-8"), key)
    with open(dest_file, "w") as of:
            of.write(str(data))
    """


@handles("help", "h", "usage")
def usage(none=None):
    print(usage_str)


def write_encrypted(name, data):
    outfile = check_file(name) + ".gpg"

    gpg = gnupg.GPG()
    key = config["keyid"]
    data = gpg.encrypt(data.encode("utf-8"), key)

    data_path = os.path.dirname(outfile)
    if not os.path.exists(data_path):
        pathlib.Path(data_path).mkdir(parents=True)

    with open(outfile, "w") as of:
        of.write(str(data))




@handles("add", "a")
def add(name=None):
    if name is None:
        name = prompt_name()

    outfile = check_file(name) + ".gpg"

    pass1 = prompt("Password:", is_password=True)
    pass2 = prompt("Verify:", is_password=True)

    if pass1 != pass2:
        print("Passwords do not match.")
        sys.exit(-1)

    write_encrypted(name, pass1)


@handles("import")
def handle_import(name: str):
    if name is None:
        print("Key name not specified.", file=sys.stderr)
        sys.exit(-1)
    
    data = sys.stdin.read()
    write_encrypted(name, data)

@handles("import-otp")
def otp_import(*args):
    for data in sys.stdin.readlines():
        data = data.strip()
        otp = pyotp.parse_uri(data)
        if otp.issuer is not None:
            name = os.path.join("otp", otp.issuer, otp.name)
        else:
            name = os.path.join("otp", otp.name)
        write_encrypted(name, data)


@handles("show", "s")
def show(name=None):
    if name is None:
        name = prompt_name(True)

    decrypted = str(decrypt(name))

    # If it's an OTP url, return the token instead
    # of the data.
    if is_otp_url(decrypted):
        decrypted = totp(decrypted)

    print(decrypted)


@handles("list", "ls")
def list(_=None):
    secrets = get_secret_names()
    for s in secrets:
        print(s)


def handle(cmd, args):
    if cmd in ["u", "usage"]:
        usage(*args)
        sys.exit(0)

    if cmd in ["init", "i"]:
        init(*args)
        sys.exit(0)

    if not os.path.isdir(base_dir):
        print("Vault not initialized. You can initialize using:")
        print("     vault init <gpg key>")
        sys.exit(-1)

    if not cmd in command_handlers:
        print(f"Command not found {cmd}")
        usage(*args)
        sys.exit(-1)

    read_config()
    command_handlers[cmd](*args)


if __name__ == "__main__":
    cmd = "usage"
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
    handle(cmd, sys.argv[2:])
