#!/usr/bin/env python3
"""
Migra configuración de router Juniper vMX a NetBox
Parsea archivo .cfg en formato 'set' y crea interfaces, BGP, y objetos relacionados
"""

import re
import requests
from typing import Dict, List, Optional
import sys

class NetBoxMigrator:
    def __init__(self):
        self.netbox_url = "https://humble-space-telegram-x5544pjgrr6wf69q9-8000.app.github.dev"
        self.netbox_token = "nbt_fED61clA3RXx.nOapq82PusjRWi5KN6gleijvCceQRqYbreJAqLay"
        self.headers = {
            "Authorization": f"Bearer {self.netbox_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    # === FUNCIONES EXISTENTES (interfaces e IPs) ===
    def get_object_by_name(self, endpoint: str, name: str, **params) -> Optional[Dict]:
        """Obtiene objeto por nombre desde NetBox"""
        url = f"{self.netbox_url}/api/{endpoint}/"
        params['name'] = name
        try:
            resp = self.session.get(url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if data['count'] > 0:
                return data['results'][0]
        except Exception as e:
            print(f"❌ Error obteniendo {endpoint} '{name}': {e}")
        return None
    
    def get_or_create_interface(self, device_id: int, interface_name: str, 
                              description: str = "", enabled: bool = True) -> Optional[Dict]:
        """Obtiene o crea interfaz en NetBox"""
        url = f"{self.netbox_url}/api/dcim/interfaces/"
        try:
            resp = self.session.get(url, params={
                "device_id": device_id,
                "name": interface_name
            }, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            if data['count'] > 0:
                interface = data['results'][0]
                if interface['description'] != description:
                    update_data = {"description": description}
                    update_url = f"{url}{interface['id']}/"
                    self.session.patch(update_url, json=update_data)
                return interface
            
            interface_data = {
                "device": device_id,
                "name": interface_name,
                "description": description,
                "enabled": enabled,
                "type": "1000base-t"
            }
            resp = self.session.post(url, json=interface_data, timeout=10)
            resp.raise_for_status()
            return resp.json()
            
        except Exception as e:
            print(f"❌ Error con interfaz {interface_name}: {e}")
            return None
    
    def get_or_create_ip_address(self, address: str, interface_id: int) -> bool:
        """Obtiene o crea dirección IP en NetBox"""
        url = f"{self.netbox_url}/api/ipam/ip-addresses/"
        try:
            resp = self.session.get(url, params={"address": address}, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            if data['count'] > 0:
                ip_obj = data['results'][0]
                if ip_obj.get('assigned_object_id') != interface_id:
                    update_data = {
                        "assigned_object_type": "dcim.interface",
                        "assigned_object_id": interface_id,
                        "status": "active"
                    }
                    update_url = f"{url}{ip_obj['id']}/"
                    self.session.patch(update_url, json=update_data)
            else:
                ip_data = {
                    "address": address,
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": interface_id,
                    "status": "active"
                }
                self.session.post(url, json=ip_data, timeout=10)
            return True
        except Exception as e:
            print(f"❌ Error con IP {address}: {e}")
            return False
    
    # === NUEVAS FUNCIONES PARA BGP ===
    
    def create_custom_fields(self):
        """Crea los custom fields necesarios para BGP"""
        print("🔧 Creando custom fields...")
        
        custom_fields = [
            {
                "name": "local_asn",
                "object_types": ["dcim.device"],
                "type": "text",
                "description": "Local ASN for BGP"
            },
            {
                "name": "as_path_prepend_count", 
                "object_types": ["netbox_bgp.routingpolicyrule"],
                "type": "integer",
                "description": "Number of times to prepend AS path"
            },
            {
                "name": "apply_community",
                "object_types": ["netbox_bgp.routingpolicyrule"],
                "type": "text",
                "description": "Community to apply"
            },
            {
                "name": "local_preference",
                "object_types": ["netbox_bgp.routingpolicyrule"],
                "type": "text", 
                "description": "Local preference value"
            }
        ]
        
        url = f"{self.netbox_url}/api/extras/custom-fields/"
        
        for cf in custom_fields:
            # Verificar si ya existe
            check_resp = self.session.get(url, params={"name": cf["name"]})
            if check_resp.json()['count'] == 0:
                try:
                    create_resp = self.session.post(url, json=cf)
                    create_resp.raise_for_status()
                    print(f"   ✅ Custom field '{cf['name']}' creado")
                except Exception as e:
                    print(f"   ❌ Error creando '{cf['name']}': {e}")
                    if 'create_resp' in locals():
                        print(f"   💡 Respuesta: {create_resp.text}")
            else:
                print(f"   ℹ️  Custom field '{cf['name']}' ya existe")

    def get_or_create_community(self, value: str) -> Optional[Dict]:
        """Obtiene o crea comunidad BGP"""
        url = f"{self.netbox_url}/api/plugins/bgp/community/"
        resp = self.session.get(url, params={"value": value})
        if resp.json()['count'] > 0:
            return resp.json()['results'][0]
        
        # Crear nueva comunidad
        community_data = {"value": value}
        resp = self.session.post(url, json=community_data)
        resp.raise_for_status()
        print(f"   ✅ Comunidad BGP '{value}' creada")
        return resp.json()
    
    def get_or_create_prefix_list(self, name: str, family: str = "ipv6") -> Optional[Dict]:
        """Obtiene o crea lista de prefijos"""
        url = f"{self.netbox_url}/api/plugins/bgp/prefix-list/"
        resp = self.session.get(url, params={"name": name})
        if resp.json()['count'] > 0:
            return resp.json()['results'][0]
        
        # Crear nueva lista de prefijos
        prefix_list_data = {
            "name": name,
            "family": family,
            "description": f"Prefix list migrated from Juniper config"
        }
        resp = self.session.post(url, json=prefix_list_data)
        resp.raise_for_status()
        print(f"   ✅ Prefix list '{name}' creada")
        return resp.json()
    
    def get_or_create_prefix_list_rule(self, prefix_list_id: int, prefix: str, 
                                    index: int = 10, action: str = "permit") -> bool:
        """Obtiene o crea regla de lista de prefijos"""
        url = f"{self.netbox_url}/api/plugins/bgp/prefix-list-rule/"
        resp = self.session.get(url, params={
            "prefix_list": prefix_list_id,
            "prefix": prefix
        })
        
        if resp.json()['count'] > 0:
            return True
        
        # Crear nueva regla
        rule_data = {
            "prefix_list": prefix_list_id,
            "prefix": prefix,
            "index": index,
            "action": action
        }
        self.session.post(url, json=rule_data)
        print(f"   ✅ Regla '{prefix}' en prefix list creada")
        return True

class JuniperConfigParser:
    def __init__(self, config_file: str):
        with open(config_file, 'r') as f:
            self.config_lines = [line.strip() for line in f.readlines() if line.strip()]
    
    def parse_interfaces(self) -> List[Dict]:
        """Extrae interfaces y direcciones IP"""
        interfaces = {}
        for line in self.config_lines:
            if line.startswith('set interfaces '):
                # Parsear direcciones IP
                ip_pattern = r'set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+(inet6?|inet)\s+address\s+(\S+)'
                ip_match = re.search(ip_pattern, line)
                if ip_match:
                    interface_name = ip_match.group(1)
                    family = ip_match.group(2)
                    address = ip_match.group(3)
                    
                    if interface_name not in interfaces:
                        interfaces[interface_name] = {
                            'name': interface_name,
                            'description': '',
                            'ipv4_addresses': [],
                            'ipv6_addresses': [],
                            'enabled': True
                        }
                    
                    if family == 'inet6':
                        interfaces[interface_name]['ipv6_addresses'].append(address)
                    else:
                        interfaces[interface_name]['ipv4_addresses'].append(address)
                
                # Parsear descripciones
                desc_pattern = r'set\s+interfaces\s+(\S+)\s+description\s+(.+)'
                desc_match = re.search(desc_pattern, line)
                if desc_match:
                    interface_name = desc_match.group(1)
                    description = desc_match.group(2).strip('"\'')
                    if interface_name not in interfaces:
                        interfaces[interface_name] = {
                            'name': interface_name,
                            'description': description,
                            'ipv4_addresses': [],
                            'ipv6_addresses': [],
                            'enabled': True
                        }
                    else:
                        interfaces[interface_name]['description'] = description
        
        return list(interfaces.values())
    
    def parse_bgp_config(self) -> Dict:
        """Extrae configuración BGP completa"""
        bgp_data = {
            'communities': set(),
            'prefix_lists': {},
            'routing_policies': {}
        }
        
        for line in self.config_lines:
            # Parsear communities
            comm_pattern = r'set\s+policy-options\s+community\s+(\S+)\s+members\s+(\S+)'
            comm_match = re.search(comm_pattern, line)
            if comm_match:
                comm_value = comm_match.group(2)
                bgp_data['communities'].add(comm_value)
            
            # Parsear prefix lists
            prefix_pattern = r'set\s+policy-options\s+prefix-list\s+(\S+)\s+(\S+)'
            prefix_match = re.search(prefix_pattern, line)
            if prefix_match:
                pl_name = prefix_match.group(1)
                prefix = prefix_match.group(2)
                if pl_name not in bgp_data['prefix_lists']:
                    bgp_data['prefix_lists'][pl_name] = []
                bgp_data['prefix_lists'][pl_name].append(prefix)
        
        return bgp_data

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 migrate_juniper_to_netbox.py <archivo_config.cfg>")
        sys.exit(1)
    
    config_file = sys.argv[1]
    DEVICE_NAME = "rt-core"
    
    print("🚀 Iniciando migración de configuración Juniper a NetBox...")
    
    # Parsear configuración
    parser = JuniperConfigParser(config_file)
    
    # === PASO 1: CREAR CUSTOM FIELDS ===
    print("\n📋 Paso 1: Configurando custom fields...")
    migrator = NetBoxMigrator()
    migrator.create_custom_fields()
    
    # === PASO 2: PROCESAR COMMUNITIES ===
    print("\n📋 Paso 2: Procesando communities BGP...")
    bgp_config = parser.parse_bgp_config()
    for comm_value in bgp_config['communities']:
        migrator.get_or_create_community(comm_value)
    
    # === PASO 3: PROCESAR PREFIX LISTS ===
    print("\n📋 Paso 3: Procesando prefix lists...")
    for pl_name, prefixes in bgp_config['prefix_lists'].items():
        # Determinar familia (ipv4 o ipv6)
        family = "ipv6" if ":" in prefixes[0] else "ipv4"
        prefix_list_obj = migrator.get_or_create_prefix_list(pl_name, family)
        if prefix_list_obj:
            for i, prefix in enumerate(prefixes, 1):
                migrator.get_or_create_prefix_list_rule(
                    prefix_list_id=prefix_list_obj['id'],
                    prefix=prefix,
                    index=i * 10
                )
    
    # === PASO 4: PROCESAR INTERFACES E IPs ===
    print("\n📋 Paso 4: Procesando interfaces e IPs...")
    interfaces = parser.parse_interfaces()
    if interfaces:
        device = migrator.get_object_by_name("dcim/devices", DEVICE_NAME)
        if device:
            device_id = device['id']
            for intf in interfaces:
                interface_obj = migrator.get_or_create_interface(
                    device_id=device_id,
                    interface_name=intf['name'],
                    description=intf['description']
                )
                if interface_obj:
                    all_ips = intf['ipv4_addresses'] + intf['ipv6_addresses']
                    for ip_addr in all_ips:
                        migrator.get_or_create_ip_address(ip_addr, interface_obj['id'])
    
    print("\n🎉 Migración BGP completada exitosamente!")

if __name__ == "__main__":
    main()
