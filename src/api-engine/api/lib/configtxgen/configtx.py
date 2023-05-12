#
# SPDX-License-Identifier: Apache-2.0
#
import yaml
import os
from copy import deepcopy
from api.config import CELLO_HOME


def load_configtx(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return yaml.load(f, Loader=yaml.FullLoader)


class ConfigTX:
    """Class represents crypto-config yaml."""

    def __init__(self, network, filepath=CELLO_HOME, orderer=None, raft_option=None, template_path="/opt/config/configtx.yaml"):
        """init ConfigTX
                param:
                    network: network's name
                    orderer: configuration of output block
                    raft_option: configuration of raft
                    filepath: cello's working directory
                return:
        """
        self.filepath = filepath
        self.network = network
        self.template = load_configtx(template_path)
        # self.orderer = {'BatchTimeout': '2s',
        #                 'OrdererType': "etcdraft",
        #                 'BatchSize': {'AbsoluteMaxBytes': '98 MB',
        #                               'MaxMessageCount': 2000,
        #                               'PreferredMaxBytes': '10 MB'}} if not orderer else orderer
        # self.raft_option = {'TickInterval': "600ms",
        #                     'ElectionTick': 10,
        #                     'HeartbeatTick': 1,
        #                     'MaxInflightBlocks': 5,
        #                     'SnapshotIntervalSize': "20 MB"} if not raft_option else raft_option

    def create(self, consensus, orderers, peers, orderer_cfg=None, application=None, option=None):
        """create the cryptotx.yaml
                param:
                    consensus:consensus
                    orderers:the list of orderer
                    peers: the list of peer
                    orderer_cfg: the config of orderer
                    application: application
                    option: option
                return:
        """
        OrdererDefaults = self.template["Orderer"]
        ChannelDefaults = self.template["Channel"]
        ApplicationDefaults = self.template["Application"]
        ChannelCapabilities = self.template["Capabilities"]["Channel"]
        OrdererCapabilities = self.template["Capabilities"]["Orderer"]
        ApplicationCapabilities = self.template["Capabilities"]["Application"]

        OrdererOrganizations = []
        OrdererAddress = []
        Consenters = []

        for orderer in orderers:
            OrdererMSP = orderer["name"].capitalize() + "Orderer"
            OrdererOrg = dict(
                Name=orderer["name"].split(".")[0].capitalize() + "Orderer",
                ID=f'{OrdererMSP}MSP',
                MSPDir=f"""{self.filepath}/{orderer["name"]}/crypto-config/ordererOrganizations/{orderer['name'].split(".", 1)[1]}/msp""",
                Policies=dict(
                    Readers=dict(
                        Type="Signature", Rule=f"OR('{OrdererMSP}MSP.member')"
                    ),
                    Writers=dict(
                        Type="Signature", Rule=f"OR('{OrdererMSP}MSP.member')"
                    ),
                    Admins=dict(
                        Type="Signature", Rule=f"OR('{OrdererMSP}MSP.admin')"
                    ),
                ),
            )
            for host in orderer['hosts']:
                OrdererAddress.append(
                    f"""{host['name']}.{orderer['name'].split(".", 1)[1]}:7050"""
                )
                Consenters.append(
                    dict(
                        Host=f"""{host['name']}.{orderer['name'].split(".", 1)[1]}""",
                        Port=7050,
                        ClientTLSCert=f"""{self.filepath}/{orderer['name']}/crypto-config/ordererOrganizations/{orderer['name'].split(".", 1)[1]}/orderers/{host['name']}.{orderer['name'].split(".", 1)[1]}/tls/server.crt""",
                        ServerTLSCert=f"""{self.filepath}/{orderer['name']}/crypto-config/ordererOrganizations/{orderer['name'].split(".", 1)[1]}/orderers/{host['name']}.{orderer['name'].split(".", 1)[1]}/tls/server.crt""",
                    )
                )
            OrdererOrg["OrdererEndpoints"] = deepcopy(OrdererAddress)
            OrdererOrganizations.append(OrdererOrg)

        PeerOrganizations = []

        for peer in peers:
            PeerMSP = peer["name"].capitalize()
            PeerOrganizations.append(
                dict(
                    Name=peer["name"].split(".")[0].capitalize(),
                    ID=f'{PeerMSP}MSP',
                    MSPDir=f"{self.filepath}/{peer['name']}/crypto-config/peerOrganizations/{peer['name']}/msp",
                    Policies=dict(
                        Readers=dict(
                            Type="Signature", Rule=f"OR('{PeerMSP}MSP.member')"
                        ),
                        Writers=dict(
                            Type="Signature", Rule=f"OR('{PeerMSP}MSP.member')"
                        ),
                        Admins=dict(
                            Type="Signature", Rule=f"OR('{PeerMSP}MSP.admin')"
                        ),
                        Endorsement=dict(
                            Type="Signature", Rule=f"OR('{PeerMSP}MSP.member')"
                        ),
                    ),
                )
            )
        Organizations = OrdererOrganizations + PeerOrganizations
        Capabilities = dict(
            Channel=ChannelCapabilities,
            Orderer=OrdererCapabilities,
            Application=ApplicationCapabilities
        )
        Application = deepcopy(ApplicationDefaults)
        Application["Capabilities"] = Capabilities["Application"]
        Orderer = deepcopy(OrdererDefaults)
        Orderer["Addresses"] = deepcopy(OrdererAddress)
        Orderer["Policies"] = dict(
                Readers=dict(Type="ImplicitMeta", Rule="ANY Readers"),
                Writers=dict(Type="ImplicitMeta", Rule="ANY Writers"),
                Admins=dict(Type="ImplicitMeta", Rule="MAJORITY Admins"),
                BlockValidation=dict(Type="ImplicitMeta", Rule="ANY Writers")
                 )
        Orderer["EtcdRaft"]["Consenters"] = deepcopy(Consenters)
        Channel = deepcopy(ChannelDefaults)
        Channel["Capabilities"] = Capabilities["Channel"]
        Profiles = {"TwoOrgsOrdererGenesis": deepcopy(Channel)}
        Profiles["TwoOrgsOrdererGenesis"]["Orderer"] = deepcopy(Orderer)
        Profiles["TwoOrgsOrdererGenesis"]["Orderer"]["Organizations"] = OrdererOrganizations
        Profiles["TwoOrgsOrdererGenesis"]["Orderer"]["Capabilities"] = Capabilities["Orderer"]
        Profiles["TwoOrgsOrdererGenesis"]["Consortiums"] = {'SampleConsortium': {'Organizations': deepcopy(PeerOrganizations)}}

        configtx = dict(
            Organizations=Organizations,
            Capabilities=Capabilities,
            Application=Application,
            Orderer=Orderer,
            Channel=Channel,
            Profiles=Profiles
        )
        os.system(f'mkdir -p {self.filepath}/{self.network}')

        with open(f'{self.filepath}/{self.network}/configtx.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(configtx, f, sort_keys=False)

    def createChannel(self, name, organizations):
        """create the channel.tx
                param:
                  name: name of channel
                  organizations: Organizations ready to join the channel
                return:
        """
        try:
            with open(f'{self.filepath}/{self.network}/configtx.yaml', 'r+', encoding='utf-8') as f:
                configtx = yaml.load(f, Loader=yaml.FullLoader)
                Profiles = configtx["Profiles"]
                Channel = configtx["Channel"]
                Application = configtx["Application"]
                Capabilities = configtx["Capabilities"]["Application"]
                PeerOrganizations = []
                for org in configtx["Organizations"]:
                    PeerOrganizations.extend(
                        org
                        for item in organizations
                        if org["ID"] == f"{item.capitalize()}MSP"
                    )
                if not PeerOrganizations:
                    raise Exception("can't find organnization")
                Profiles[name] = deepcopy(Channel)
                Profiles[name]["Consortium"] = "SampleConsortium"
                Profiles[name]["Application"] = deepcopy(Application)
                Profiles[name]["Application"]["Organizations"] = deepcopy(PeerOrganizations)
                Profiles[name]["Application"]["Capabilities"] = deepcopy(Capabilities)

            with open(f'{self.filepath}/{self.network}/configtx.yaml', 'w', encoding='utf-8') as f:
                yaml.safe_dump(configtx, f, sort_keys=False)

        except Exception as e:
            err_msg = f"Configtx create channel failed for {e}!"
            raise Exception(err_msg)


if __name__ == "__main__":
    orderers = [{"name": "org1.cello.com", "hosts": [{"name": "orderer1", "port": 8051}]}]
    # peers = [{"name": "org1.cello.com", "hosts": [{"name": "foo", "port": 7051},{"name": "car", "port": 7052}]},
    #         {"name": "org2.cello.com", "hosts": [{"name": "zoo", "port": 7053}]}]
    peers = [{"name": "org1.cello.com", "hosts": [{"name": "foo", "port": 7051}, {"name": "car", "port": 7052}]}]
    ConfigTX("test3").create(consensus="etcdraft", orderers=orderers, peers=peers)
    # tx = ConfigTX("test3")
    # print(tx.template)
