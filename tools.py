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


class Vault:

    def __init__(self, config=None, base_dir=None):
        if base_dir is None:
            base_dir = os.path.expanduser("~/.vault")

        if config is None:
            config = read_config(base_dir)

        if config is None:
            raise Exception("Vault is not initialized.")

        self._base_dir = base_dir
        self._config = config

    def list(self, include_directories=False):
        secrets_list = []
        for r, d, f in os.walk(self._base_dir):
            if include_directories:
                fd = r[len(self._base_dir) + 1:]
                secrets_list.append(fd + os.sep)

            for file in f:
                if not file.endswith(".gpg"):
                    continue

                ff = os.path.join(r, file)
                fd = ff[len(self._base_dir) + 1:-4]
                secrets_list.append(fd)

        return secrets_list

    def check_file(self, path):
        path = os.path.join(self._base_dir, path)
        base_path = pathlib.Path(self._base_dir).resolve()
        resolved = pathlib.Path(path).resolve()
        if base_path not in (resolved, *resolved.parents):
            raise Exception("Tricky path detected.")
        return str(resolved)

    def remove(self, name):
        path = self.check_file(name) + ".gpg"
        if not os.path.exists(path):
            raise Exception("Key not found.")

        # TODO: Maybe we should check for empty directories as well?
        os.remove(path)

    def write(self, name, data):
        outfile = self.check_file(name) + ".gpg"

        gpg = gnupg.GPG()
        key = self._config["keyid"]
        data = gpg.encrypt(data.encode("utf-8"), key)

        data_path = os.path.dirname(outfile)
        if not os.path.exists(data_path):
            pathlib.Path(data_path).mkdir(parents=True)

        with open(outfile, "w") as of:
            of.write(str(data))

    def decrypt(self, name):
        infile = self.check_file(name) + ".gpg"

        if not os.path.exists(infile):
            raise Exception("Secret not found.")

        with open(infile, "r") as f:
            data = f.read()
        gpg = gnupg.GPG()

        return gpg.decrypt(data)

    def try_decrypt(self, name):
        try:
            return self.decrypt(name)
        except Exception as _:
            return None
