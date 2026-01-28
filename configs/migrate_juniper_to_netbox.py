#!/usr/bin/env python3
"""
Migra configuración de router Juniper vMX a NetBox
Parsea archivo .cfg en formato 'set' y crea interfaces, IPs
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
    
    def get_object_by_name(self, endpoint: str, name: str) -> Optional[Dict]:
        """Obtiene objeto por nombre desde NetBox"""
        url = f"{self.netbox_url}/api/{endpoint}/"
        params = {"name": name}
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

def parse_juniper_config(config_file):
    """Parsea archivo de configuración Juniper con mejor manejo de errores"""
    interfaces = {}
    
    try:
        with open(config_file, 'r') as f:
            lines = f.readlines()
        
        print(f"🔍 Analizando {len(lines)} líneas...")
        
        for i, line in enumerate(lines, 1):
            original_line = line.strip()
            if not original_line:
                continue
                
            print(f"   Línea {i}: '{original_line}'")
            
            # Usar expresión regular para parsear mejor
            # Patrón para direcciones IP
            ip_pattern = r'set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+(inet6?|inet)\s+address\s+(\S+)'
            ip_match = re.search(ip_pattern, original_line)
            
            if ip_match:
                interface_name = ip_match.group(1)
                family = ip_match.group(2)  # inet o inet6
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
                
                print(f"   ✅ IP encontrada: {address} en {interface_name} ({family})")
                continue
            
            # Patrón para descripciones
            desc_pattern = r'set\s+interfaces\s+(\S+)\s+description\s+(.+)'
            desc_match = re.search(desc_pattern, original_line)
            
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
                
                print(f"   ✅ Descripción encontrada: {description} en {interface_name}")
        
        return list(interfaces.values())
        
    except Exception as e:
        print(f"❌ Error al leer el archivo: {e}")
        return []

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 migrate_juniper_to_netbox.py <archivo_config.cfg>")
        sys.exit(1)
    
    config_file = sys.argv[1]
    DEVICE_NAME = "rt-core"
    
    print(f"📡 Parseando configuración de {config_file}...")
    
    # Parsear configuración con regex
    interfaces = parse_juniper_config(config_file)
    print(f"✅ Encontradas {len(interfaces)} interfaces")
    
    if not interfaces:
        print("⚠️  No se encontraron interfaces. Verifica el formato del archivo.")
        print("💡 Formato esperado:")
        print("   set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64")
        print("   set interfaces lo0 unit 0 family inet address 10.1.0.1/32")
        return
    
    for intf in interfaces:
        all_ips = intf['ipv4_addresses'] + intf['ipv6_addresses']
        if all_ips:
            ip_list = ', '.join(all_ips)
            desc = f" ({intf['description']})" if intf['description'] else ""
            print(f"   {intf['name']}{desc}: {ip_list}")
    
    print("🔌 Conectando a NetBox...")
    
    # Inicializar migrador
    migrator = NetBoxMigrator()
    
    # Obtener dispositivo
    device = migrator.get_object_by_name("dcim/devices", DEVICE_NAME)
    if not device:
        print(f"❌ Dispositivo '{DEVICE_NAME}' no encontrado en NetBox")
        return
    
    device_id = device['id']
    print(f"✅ Dispositivo encontrado: {device['name']} (ID: {device_id})")
    
    # Procesar interfaces e IPs
    success_count = 0
    for intf in interfaces:
        interface_obj = migrator.get_or_create_interface(
            device_id=device_id,
            interface_name=intf['name'],
            description=intf['description']
        )
        
        if interface_obj:
            print(f"✅ Interfaz {intf['name']} procesada")
            all_ips = intf['ipv4_addresses'] + intf['ipv6_addresses']
            for ip_addr in all_ips:
                if migrator.get_or_create_ip_address(ip_addr, interface_obj['id']):
                    print(f"   ✅ IP {ip_addr} asignada")
                    success_count += 1
        else:
            print(f"❌ Falló procesamiento de {intf['name']}")
    
    print(f"🎉 Migración completada! {success_count} direcciones IP procesadas.")

if __name__ == "__main__":
    main()
