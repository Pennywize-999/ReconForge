import os
from typing import List, Tuple
from bs4 import BeautifulSoup

from reconforge.core.models import Host, Port, Service, Finding, Confidence, Technology
from reconforge.parsers.base import BaseParser


class NmapXMLParser(BaseParser):
    @classmethod
    def can_parse(cls, file_path: str) -> bool:
        if not file_path.endswith('.xml'):
            return False
        content = cls.read_file_safe(file_path)[:1000]
        return "<?xml" in content and "<nmaprun" in content

    @classmethod
    def parse(cls, file_path: str) -> Tuple[List[Host], List[Finding], List[str]]:
        hosts: List[Host] = []
        findings: List[Finding] = []
        errors: List[str] = []

        content = cls.read_file_safe(file_path)
        if not content:
            return hosts, findings, ["Failed to read Nmap XML file"]

        try:
            soup = BeautifulSoup(content, 'xml')

            for host_node in soup.find_all('host'):
                status_node = host_node.find('status')
                status = status_node['state'] if status_node and status_node.has_attr('state') else "unknown"

                ipv4 = ""
                ipv6 = ""
                mac = ""

                for addr in host_node.find_all('address'):
                    if addr.get('addrtype') == 'ipv4':
                        ipv4 = addr.get('addr')
                    elif addr.get('addrtype') == 'ipv6':
                        ipv6 = addr.get('addr')
                    elif addr.get('addrtype') == 'mac':
                        mac = addr.get('addr')

                ip = ipv4 if ipv4 else (ipv6 if ipv6 else "unknown")
                if ip == "unknown":
                    continue

                host = Host(ip=ip, status=status, ipv6=ipv6, mac=mac)

                hostnames = host_node.find('hostnames')
                if hostnames:
                    for hname in hostnames.find_all('hostname'):
                        if hname.has_attr('name'):
                            host.hostnames.append(hname['name'])

                os_node = host_node.find('os')
                if os_node:
                    for osmatch in os_node.find_all('osmatch'):
                        name = osmatch.get('name')
                        if name and name not in host.os_guesses:
                            host.os_guesses.append(name)
                    for oscpe in os_node.find_all('cpe'):
                        cpe_txt = oscpe.text.strip()
                        if cpe_txt and cpe_txt not in host.os_cpes:
                            host.os_cpes.append(cpe_txt)

                ports_node = host_node.find('ports')
                if ports_node:
                    for port_node in ports_node.find_all('port'):
                        port_id = int(port_node['portid'])
                        protocol = port_node['protocol']
                        state_node = port_node.find('state')
                        state = state_node['state'] if state_node else "unknown"

                        service = None
                        service_node = port_node.find('service')
                        if service_node:
                            s_name = service_node.get('name', '')
                            s_product = service_node.get('product', '')
                            s_version = service_node.get('version', '')
                            cpe_nodes = service_node.find_all('cpe')
                            s_cpe = cpe_nodes[0].text if cpe_nodes else ""

                            techs = []
                            if s_product:
                                techs.append(Technology(
                                    name=s_product,
                                    version=s_version,
                                    sources=[os.path.basename(file_path)],
                                    detected_values=[f"{s_product} {s_version}"],
                                    confidence=Confidence.HIGH,
                                ))

                            service = Service(
                                name=s_name,
                                product=s_product,
                                version=s_version,
                                cpe=s_cpe,
                                technologies=techs,
                            )

                        port = Port(
                            number=port_id,
                            protocol=protocol,
                            state=state,
                            service=service,
                        )
                        host.ports.append(port)

                hosts.append(host)

        except Exception as e:
            errors.append(f"Error parsing Nmap XML {file_path}: {str(e)}")

        return hosts, findings, errors
