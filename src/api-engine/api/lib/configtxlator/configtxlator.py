#
# SPDX-License-Identifier: Apache-2.0
#
from subprocess import call, run
from api.config import FABRIC_TOOL


class ConfigTxLator:
    """
    Class represents configtxlator CLI.
    """

    def __init__(self, configtxlator=FABRIC_TOOL, version="2.2.0"):
        self.configtxlator = f"{configtxlator}/configtxlator"
        self.version = version

    def proto_encode(self, input, type, output):
        """
        Converts a JSON document to protobuf.

        params:
            input: A file containing the JSON document.
            type:  The type of protobuf structure to encode to. For example, 'common.Config'.
            output: A file to write the output to.
        """
        try:
            call(
                [
                    self.configtxlator,
                    "proto_encode",
                    f"--input={input}",
                    f"--type={type}",
                    f"--output={output}",
                ]
            )
        except Exception as e:
            err_msg = "configtxlator proto decode fail! "
            raise Exception(err_msg + str(e))

    def proto_decode(self, input, type):
        """
        Converts a proto message to JSON.

        params:
            input: A file containing the JSON document.
            type:  The type of protobuf structure to decode to. For example, 'common.Config'.
        return:
            config
        """
        try:
            res = run(
                [
                    self.configtxlator,
                    "proto_decode",
                    f"--type={type}",
                    f"--input={input}",
                ],
                capture_output=True,
            )
            return res.stdout if res.returncode == 0 else res.stderr
        except Exception as e:
            err_msg = "configtxlator proto decode fail! "
            raise Exception(err_msg + str(e))

    def compute_update(self, original, updated, channel_id, output):
        """
        Takes two marshaled common.Config messages and computes the config update which
        transitions between the two.

        params:
            original: The original config message.
            updated: The updated config message.
            channel_id: The name of the channel for this update.
            output: A file to write the JSON document to.
        """
        try:
            call(
                [
                    self.configtxlator,
                    "compute_update",
                    f"--original={original}",
                    f"--updated={updated}",
                    f"--channel_id={channel_id}",
                    f"--output={output}",
                ]
            )
        except Exception as e:
            err_msg = "configtxlator compute update fail! "
            raise Exception(err_msg + str(e))
