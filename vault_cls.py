import os
import pathlib
import gnupg
import getpass
from tools import read_config


class Vault:

    def __init__(self, config=None, base_dir=None, ask_password=False):
        """
        Vault class manages secrets.

        Parameters:
            config - dictionary containing configuration (read form .config.yml if not found)
            base_dir - vault directory - defaults to ~/.vault
        """
        if base_dir is None:
            base_dir = os.path.expanduser("~/.vault")

        if config is None:
            config = read_config(base_dir)

        if config is None:
            raise Exception("Vault is not initialized.")
        
        self.ask_password = ask_password
        self._base_dir = base_dir
        self._config = config

    def list(self, include_directories=False):
        """
        Retrieve a list of secrets stored int he vault.

        #parameters:
            include_directories - when true, the bare directories are included in the list.
        """
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
        """
        Expands the name path under the vault directory.  Ensures the resulting
        file is under the vault folder (in the event indirect references are used)
        """
        path = os.path.join(self._base_dir, path)
        base_path = pathlib.Path(self._base_dir).resolve()
        resolved = pathlib.Path(path).resolve()
        if base_path not in (resolved, *resolved.parents):
            raise Exception("Tricky path detected.")
        return str(resolved)

    def remove(self, name):
        """
        Removes a secret from the vault.

        Parameters:
            name - the name of the secret
        """
        path = self.check_file(name) + ".gpg"
        if not os.path.exists(path):
            raise Exception("Key not found.")

        # TODO: Maybe we should check for empty directories as well?
        os.remove(path)

    def write(self, name: str, data: str):
        """
        Writes (or overwrites) a new secret to the vault.

        Parameters:
            name - the name of the secret
            data - string containing the secret data.
        """
        outfile = self.check_file(name) + ".gpg"

        gpg = gnupg.GPG(use_agent=True)
        key = self._config["keyid"]
        data = gpg.encrypt(data.encode("utf-8"), key)

        data_path = os.path.dirname(outfile)
        if not os.path.exists(data_path):
            pathlib.Path(data_path).mkdir(parents=True)

        with open(outfile, "w") as of:
            of.write(str(data))


    def _maybe_prompt_password(self):
        if not self.ask_password:
            return None

        passphrase = getpass.getpass("Key Passphrase: ")
        return passphrase

    def decrypt(self, name):
        """
        Returns the secret.

        Parameters:
            name - name of the secret
        """
        infile = self.check_file(name) + ".gpg"

        if not os.path.exists(infile):
            raise Exception("Secret not found.")

        with open(infile, "r") as f:
            data = f.read()

        passphrase = self._maybe_prompt_password()
        use_agent = True
        if (passphrase is not None):
            use_agent = False

        gpg = gnupg.GPG(use_agent=use_agent)

        return gpg.decrypt(data, passphrase=passphrase)

    def try_decrypt(self, name):
        """
        Attempts to retrieve and decrypt the secret.  Returns None
        instead of throwing in the event the secret is missing.

        Parameters:
             name - the secret name.
        """
        try:
            return self.decrypt(name)
        except Exception as _:
            return None
