import pathlib
import os
import yaml
import gnupg
import secrets
import string


def generate(length=15, characters=None, digits=True, symbols=True, lowercase=True, uppercase=True):
    if characters is None:
        characters = ""
        if digits:
            characters += string.digits
        if lowercase:
            characters += string.ascii_lowercase
        if uppercase:
            characters += string.ascii_uppercase
        if symbols:
            characters += string.punctuation

    if not len(characters):
        raise Exception("No characters to choose from.")

    chosen = [secrets.choice(characters) for x in range(length)]
    return "".join(chosen)


def find_key_by_name(name):
    gpg = gnupg.GPG()
    keys = gpg.list_keys(True)
    for key in keys:
        if key["keyid"] == name:
            return key

        for key_id in key["uids"]:
            if name in key_id:
                return key


def read_config(base_dir):
    config_file = os.path.join(base_dir, ".config.yml")
    if not os.path.exists(config_file):
        return None

    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
    return config


