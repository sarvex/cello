#
# SPDX-License-Identifier: Apache-2.0
#
import logging
from requests import get, post
import json

from api.lib.agent.base import AgentBase

LOG = logging.getLogger(__name__)


class DockerAgent(AgentBase):
    """Class represents docker agent."""
    def __init__(self, node=None):
        """init DockerAgent
            param:
            node:Information needed to create, start, and delete nodes, such as organizations, nodes, and so on
            return:null
        """
        if node is None:
            node = {}
        self._id = node.get("id")
        self._name = node.get("name")
        self._urls = node.get("urls")
        self._cname = node.get("container_name")

    def create(self, info):
        """
        Create node
        :param node: Information needed to create nodes
        :return: container ID
        :rtype: string
        """
        try:
            port_map = {str(port.internal): str(port.external) for port in info.get("ports")}

            data = {
                'msp': info.get("msp")[2:-1],
                'tls': info.get("tls")[2:-1],
                'bootstrap_block': info.get("bootstrap_block")[2:-1],
                'peer_config_file': info.get("config_file")[2:-1],
                'orderer_config_file': info.get("config_file")[2:-1],
                'img': 'yeasy/hyperledger-fabric:2.2.0',
                'cmd': 'bash /tmp/init.sh "peer node start"' if info.get("type") == "peer" else 'bash /tmp/init.sh "orderer"',
                'name': info.get("name"),
                'type': info.get("type"),
                'port_map': port_map.__repr__(),
                'action': 'create'
            }

            response = post(f'{self._urls}/api/v1/nodes', data=data)

            if response.status_code != 200:
                return None
            txt = json.loads(response.text)
            return txt['data']['id']
        except Exception as e:
            raise e

    def delete(self, *args, **kwargs):
        try:
            response = post(
                f'{self._urls}/api/v1/nodes/{self._cname}',
                data={'action': 'delete'},
            )
            if response.status_code == 200:
                return True
            else:
                raise response.reason
        except Exception as e:
            raise e

    def start(self, *args, **kwargs):
        try:
            response = post(
                f'{self._urls}/api/v1/nodes/{self._cname}',
                data={'action': 'start'},
            )
            if response.status_code == 200:
                return True
            else:
                raise response.reason
        except Exception as e:
            raise e

    def restart(self, *args, **kwargs):
        try:
            response = post(
                f'{self._urls}/api/v1/nodes/{self._cname}',
                data={'action': 'restart'},
            )
            if response.status_code == 200:
                return True
            else:
                raise response.reason
        except Exception as e:
            raise e

    def stop(self, *args, **kwargs):
        try:
            response = post(
                f'{self._urls}/api/v1/nodes/{self._cname}', data={'action': 'stop'}
            )
            if response.status_code == 200:
                return True
            else:
                raise response.reason
        except Exception as e:
            raise e

    def get(self, *args, **kwargs):
        try:
            response = get(f'{self._urls}/api/v1/nodes/{self._cname}')
            if response.status_code == 200:
                return True
            else:
                raise response.reason
        except Exception as e:
            raise e

    def update_config(self, config_file, node_type):
        try:
            cmd = f'bash /tmp/update.sh "{node_type} node start"'
            data = {
                'peer_config_file': config_file,
                'orderer_config_file': config_file,
                'action': 'update',
                'cmd': cmd
            }
            response = post(f'{self._urls}/api/v1/nodes/{self._cname}', data=data)
            if response.status_code == 200:
                return True
            else:
                raise response.reason
        except Exception as e:
            raise e
