#
# SPDX-License-Identifier: Apache-2.0
#
import logging

from api.lib.agent.network_base import NetworkBase
from api.common.enums import FabricNodeType
from api.utils.port_picker import find_available_ports, set_ports_mapping

LOG = logging.getLogger(__name__)

CA_IMAGE_NAME = "hyperledger/fabric-ca"


class FabricNetwork(NetworkBase):
    def __init__(self, *args, **kwargs):
        super(FabricNetwork, self).__init__(*args, **kwargs)

        self._version = kwargs.get("version")
        self._type = kwargs.get("node_type")
        self._agent_id = kwargs.get("agent_id")
        self._node_id = kwargs.get("node_id")

    def _generate_deployment(self):
        containers = []
        name = str(self._node_id)
        name = f"deploy-{name}"
        if self._type == FabricNodeType.Ca.name.lower():
            image = f"{CA_IMAGE_NAME}:{self._version}"
            environments = [
                {
                    "name": "FABRIC_CA_HOME",
                    "value": "/etc/hyperledger/fabric-ca-server",
                }
            ]
            ports = [7054]
            command = ["fabric-ca-server"]
            command_args = ["start", "-b", "admin:adminpw", "-d"]
            containers.append(
                {
                    "image": image,
                    "environments": environments,
                    "name": "ca",
                    "ports": ports,
                    "command": command,
                    "command_args": command_args,
                }
            )
        return {"containers": containers, "name": name}

    def _generate_service(self):
        name = str(self._node_id)
        deploy_name = f"deploy-{name}"
        service_name = f"service-{name}"
        ports = [7054] if self._type == FabricNodeType.Ca.name.lower() else []
        return {
            "name": service_name,
            "ports": ports,
            "selector": {"app": deploy_name},
            "service_type": "NodePort",
        }

    def _generate_ingress(self):
        name = str(self._node_id)
        service_name = f"service-{name}"
        ingress_name = f"ingress-{name}"
        ingress_paths = []
        annotations = {"nginx.ingress.kubernetes.io/ssl-redirect": "false"}
        if self._type == FabricNodeType.Ca.name.lower():
            ingress_paths = [{"port": 7054, "path": f"/{name}"}]

        return {
            "name": ingress_name,
            "service_name": service_name,
            "ingress_paths": ingress_paths,
            "annotations": annotations,
        }

    def generate_config(self, *args, **kwargs):
        return {
            "deployment": self._generate_deployment(),
            "service": self._generate_service(),
            # "ingress": self._generate_ingress(),
        }
