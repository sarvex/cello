#
# SPDX-License-Identifier: Apache-2.0
#
from subprocess import call
from api.config import CELLO_HOME, FABRIC_TOOL


class CryptoGen:
    """Class represents crypto-config tool."""

    def __init__(self, name, filepath=CELLO_HOME, cryptogen=FABRIC_TOOL, version="2.2.0"):
        """init CryptoGen
                param:
                    name: organization's name
                    cryptogen: tool path
                    version: version
                    filepath: cello's working directory
                return:
        """
        self.cryptogen = f"{cryptogen}/cryptogen"
        self.filepath = filepath
        self.version = version
        self.name = name

    def generate(self, output="crypto-config", config="crypto-config.yaml"):
        """Generate key material
                param:
                    output: The output directory in which to place artifacts
                    config: The configuration template to use
                return:
        """
        try:
            call(
                [
                    self.cryptogen,
                    "generate",
                    f"--output={self.filepath}/{self.name}/{output}",
                    f"--config={self.filepath}/{self.name}/{config}",
                ]
            )
        except Exception as e:
            err_msg = f"cryptogen generate fail for {e}!"
            raise Exception(err_msg)

    def extend(self, input="crypto-config", config="crypto-config.yaml"):
        """Extend existing network
                param:
                    input: The input directory in which existing network place
                    config: The configuration template to use
                return:
        """
        try:
            call(
                [
                    self.cryptogen,
                    "extend",
                    f"--input={self.filepath}/{self.name}/{input}",
                    f"--config={self.filepath}/{self.name}/{config}",
                ]
            )
        except Exception as e:
            err_msg = f"cryptogen extend fail for {e}!"
            raise Exception(err_msg)
