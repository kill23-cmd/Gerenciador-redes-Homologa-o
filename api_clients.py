# api_clients.py
import queue
from pyzabbix import ZabbixAPI, ZabbixAPIException
import paramiko
import threading
import urllib3
import re, os, datetime
from concurrent.futures import ThreadPoolExecutor

# Desabilita avisos de SSL inseguro
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tenta importar Netmiko (necessário para funcionalidades avançadas)
try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
except Exception as e:
    ConnectHandler = None
    NetmikoTimeoutException = Exception
    NetmikoAuthenticationException = Exception


class ZabbixClient:
    def __init__(self, url, user, password):
        try:
            self.zapi = ZabbixAPI(url)
            self.zapi.session.verify = False
            self.zapi.login(user, password)
        except ZabbixAPIException as e:
            raise ConnectionError(f"Falha ao conectar no Zabbix: {e}")

    def get_hostgroups(self):
        try:
            return self.zapi.hostgroup.get(
                output=['groupid', 'name'],
                real_hosts=True,
                sortfield='name'
            )
        except ZabbixAPIException as e:
            print(f"Erro ao buscar hostgroups: {e}")
            return []

    def get_hosts_by_groupid(self, groupid):
        try:
            return self.zapi.host.get(
                output=['hostid', 'name', 'host'],
                groupids=groupid,
                selectInventory=['os', 'hardware'],
                selectInterfaces=['ip', 'type', 'main'],
                sortfield='name'
            )
        except ZabbixAPIException as e:
            print(f"Erro ao buscar hosts: {e}")
            return []

    def get_host_items_by_key(self, hostid, item_keys):
        """Busca o último valor de uma lista de chaves de itens para um host."""
        try:
            items = self.zapi.item.get(
                output=['name', 'key_', 'lastvalue', 'units'],
                hostids=hostid,
                search={'key_': item_keys}, 
                searchByAny=True
            )
            result_map = {item['key_']: {'value': item['lastvalue'], 'units': item['units'], 'name': item['name']} for item in items}
            return result_map
            
        except ZabbixAPIException as e:
            print(f"Erro ao buscar itens do Zabbix por CHAVE: {e}")
            return {}

    def get_host_items_by_name(self, hostid, item_names):
        """Busca o último valor de uma lista de nomes de itens para um host."""
        try:
            items = self.zapi.item.get(
                output=['name', 'key_', 'lastvalue', 'units'],
                hostids=hostid,
                search={'name': item_names}, 
                searchByAny=True
            )
            result_map = {item['name']: {'value': item['lastvalue'], 'units': item['units'], 'name': item['name']} for item in items}
            return result_map
            
        except ZabbixAPIException as e:
            print(f"Erro ao buscar itens do Zabbix por NOME: {e}")
            return {}

    # --- ATUALIZADO: Funções de Problemas (Triggers) ---
    
    def get_host_problems_count(self, hostid):
        """Conta o número de Triggers ativas (Problemas) para um host."""
        try:
            triggers = self.zapi.trigger.get(
                hostids=hostid,
                value=1, # 1 = Problema
                min_severity=2, # 2 = Warning ou superior
                only_true=1,
                countOutput=True # Apenas conta os resultados
            )
            return int(triggers)
            
        except ZabbixAPIException as e:
            print(f"Erro ao contar problemas do Zabbix: {e}")
            return -1 

    def get_host_problems_list(self, hostid):
        """Busca a DESCRIÇÃO das Triggers ativas (Problemas)."""
        # Mapeia prioridade para um texto
        SEVERITY_MAP = {
            '2': 'Warning',
            '3': 'Average',
            '4': 'High',
            '5': 'Disaster'
        }
        try:
            triggers = self.zapi.trigger.get(
                hostids=hostid,
                value=1, # 1 = Problema
                min_severity=2, # 2 = Warning ou superior
                only_true=1,
                output=['description', 'priority'],
                sortfield='priority', # Ordena por prioridade
                sortorder='DESC' # Mais grave primeiro
            )
            
            # Formata a lista para exibição
            problem_list = []
            if not triggers:
                return ["Nenhum problema encontrado."]
                
            for t in triggers:
                severity = SEVERITY_MAP.get(t['priority'], 'Info')
                problem_list.append(f"[{severity.upper()}] {t['description']}")
                
            return problem_list
            
        except ZabbixAPIException as e:
            print(f"Erro ao listar problemas do Zabbix: {e}")
            return [f"Erro ao buscar problemas: {e}"]
    # --- FIM DA ATUALIZAÇÃO ---


# (O resto do arquivo api_clients.py (SSHClient, Netmiko, etc.) continua o mesmo)
# ...
class SSHClient:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # ... (resto da classe SSHClient) ...
    def execute_commands_to_queue(self, commands, output_queue):
        def run():
            try:
                output_queue.put(f"--- Conectando em {self.host} ---\n")
                self.client.connect(
                    self.host, username=self.user, password=self.password,
                    timeout=5, look_for_keys=False, allow_agent=False)
                for desc, cmd in commands:
                    stdin, stdout, stderr = self.client.exec_command(cmd)
                    for line in stdout: output_queue.put(line.strip())
                    err = stderr.read().decode('utf-8')
                    if err: output_queue.put(f"ERRO: {err}")
                    output_queue.put("--- Concluído ---\n")
                self.client.close()
                output_queue.put(f"--- Desconectado de {self.host} ---\n")
            except Exception as e:
                output_queue.put(f"*** FALHA NA CONEXÃO SSH: {e} ***\n")
            finally:
                output_queue.put(None)
        thread = threading.Thread(target=run); thread.start()

# --- (Resto das funções Netmiko: expand_interface_list, save_config_backup, etc.) ---
def expand_interface_list(iface_str):
    out = []
    if not iface_str: return out
    parts = re.split(r'\s*,\s*', iface_str.strip())
    for p in parts:
        p = p.strip()
        if not p: continue
        m = re.match(r'([A-Za-z]+[\d/]+)-(\d+)$', p)
        if m:
            if '/' in p:
                base, rng = p.rsplit('/', 1)
                if '-' in rng:
                    start, end = rng.split('-', 1)
                    try:
                        for i in range(int(start), int(end)+1): out.append(f"{base}/{i}")
                        continue
                    except: pass
        if '-' in p and '/' not in p:
            prefix = re.match(r'([A-Za-z]+)(\d+)-(\d+)$', p)
            if prefix:
                name = prefix.group(1); start = int(prefix.group(2)); end = int(prefix.group(3))
                for i in range(start, end+1): out.append(f"{name}{i}")
                continue
        out.append(p)
    return out
def save_config_backup(output, host, folder="backups"):
    os.makedirs(folder, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(folder, f"{host}_{ts}.cfg")
    with open(fname, "w", encoding="utf-8") as f: f.write(output)
    return fname
def open_connection_netmiko(host, username, password, vendor=None, port=22, secret=None, conn_timeout=30):
    if ConnectHandler is None: raise RuntimeError("Netmiko não está instalado.")
    device_type_map = {
        'cisco': 'cisco_ios', 'cisco_ios': 'cisco_ios', 'cisco_switch': 'cisco_ios',
        'cisco_router': 'cisco_ios', 'fortios': 'fortios', 'fortinet': 'fortios',
        'fortiswitch': 'fortinet', 'huawei': 'huawei', 'huawei_switch': 'huawei',
    }
    device_type = device_type_map.get((vendor or '').lower(), 'cisco_ios')
    conn_params = {
        'device_type': device_type, 'host': host, 'username': username,
        'password': password, 'port': port, 'timeout': conn_timeout,
    }
    if secret: conn_params['secret'] = secret
    return ConnectHandler(**conn_params)
def execute_commands(host, username, password, vendor=None,
                     show_commands=None, config_commands=None,
                     port=22, secret=None, timeout=30, save_backup=True, do_write=False):
    result = {'host': host, 'show': {}, 'config': {}, 'errors': [], 'backup_file': None}
    show_commands = show_commands or []; config_commands = config_commands or []
    if ConnectHandler is None: result['errors'].append("Netmiko não disponível."); return result
    try:
        conn = open_connection_netmiko(host, username, password, vendor=vendor, port=port, secret=secret, conn_timeout=timeout)
    except Exception as e:
        result['errors'].append(f"Conexão falhou: {e}"); return result
    try:
        if not vendor:
            try:
                ver = conn.send_command("show version")
                if 'Cisco' in ver: vendor = 'cisco'
                elif 'Forti' in ver or 'FortiGate' in ver: vendor = 'fortios'
                elif 'Huawei' in ver or 'VRP' in ver: vendor = 'huawei'
                else:
                    ver_forti = conn.send_command("get system status")
                    if 'Forti' in ver_forti: vendor = 'fortios'
                    else: vendor = 'cisco'
            except Exception: vendor = 'cisco'
        try:
            if vendor.startswith('cisco'): backup_out = conn.send_command("show running-config")
            elif vendor.startswith('forti'): backup_out = conn.send_command("show full-configuration")
            elif vendor.startswith('huawei'): backup_out = conn.send_command("display current-configuration")
            else: backup_out = conn.send_command("show running-config")
            if save_backup: result['backup_file'] = save_config_backup(backup_out, host)
        except Exception as e: result['errors'].append(f"Backup falhou: {e}")
        for cmd in show_commands:
            try:
                out = conn.send_command(cmd)
                result['show'][cmd] = out
            except Exception as e:
                result['show'][cmd] = f"ERROR: {e}"; result['errors'].append(f"Show cmd error [{cmd}]: {e}")
        if config_commands:
            try:
                out = conn.send_config_set(config_commands, exit_config_mode=True)
                result['config']['__block__'] = out
                if do_write:
                    try:
                        if vendor.startswith('cisco'): save_out = conn.send_command("write memory")
                        elif vendor.startswith('forti'): save_out = conn.send_command("execute config-save") 
                        elif vendor.startswith('huawei'):
                            save_out = conn.send_command("save", expect_string=r'\[Y/N\]')
                            save_out += conn.send_command("Y", expect_string=r'>')
                        else: save_out = ""
                        result['config']['__save__'] = save_out
                    except Exception as e: result['errors'].append(f"Falha ao salvar config: {e}")
            except Exception as e:
                result['errors'].append(f"Erro ao aplicar config: {e}"); result['config']['__error__'] = str(e)
    finally:
        try: conn.disconnect()
        except: pass
    return result
def restore_backup(host, username, password, backup_file, vendor=None, port=22, secret=None, timeout=30):
    result = {'host': host, 'applied_lines': 0, 'errors': [], 'backup_file': backup_file}
    if ConnectHandler is None: result['errors'].append('Netmiko não disponível.'); return result
    if not os.path.exists(backup_file): result['errors'].append('Arquivo de backup não encontrado.'); return result
    with open(backup_file, 'r', encoding='utf-8') as f: lines = [l.rstrip() for l in f.readlines() if l.strip()]
    try:
        conn = open_connection_netmiko(host, username, password, vendor=vendor, port=port, secret=secret, conn_timeout=timeout)
    except Exception as e: result['errors'].append(f'Falha conexão: {e}'); return result
    try:
        out = conn.send_config_set(lines, exit_config_mode=True)
        result['applied_lines'] = len(lines); result['output'] = out
    except Exception as e: result['errors'].append(str(e))
    finally:
        try: conn.disconnect()
        except: pass
    return result
INTERFACE_FETCH_COMMANDS = {
    'cisco_switch': 'show ip interface brief', 'cisco_router': 'show ip interface brief',
    'huawei_switch': 'display interface brief', 'fortiswitch': 'diagnose switch physical-ports summary',
    'fortinet_firewall': 'get system interface'
}
def parse_interfaces(output, profile_key):
    interfaces = []
    if profile_key in ('cisco_switch', 'cisco_router'):
        interfaces = re.findall(r'^([A-Za-z]+[\d/.]+(?::\d+)?)\s+', output, re.MULTILINE)
    elif profile_key == 'huawei_switch':
        interfaces = re.findall(r'^([A-Za-z0-9/-]+)\s+(?:up|down|\*down)', output, re.MULTILINE)
    elif profile_key == 'fortiswitch':
        interfaces = re.findall(r'^(port\d+)\s+', output, re.MULTILINE)
    elif profile_key == 'fortinet_firewall':
        interfaces = re.findall(r'name:\s+([A-Za-z0-9_.-]+)', output, re.MULTILINE)
    cleanup = ['Interface', 'Status', 'Protocol', 'Port', 'Vlan', 'PHY', '-------------------']
    return sorted(list(set([i for i in interfaces if i not in cleanup and not i.startswith('---')])))
def fetch_interfaces_from_host(host, username, password, profile_key):
    command = INTERFACE_FETCH_COMMANDS.get(profile_key)
    if not command: command = 'show ip interface brief'
    conn = None
    try:
        conn = open_connection_netmiko(host, username, password, vendor=profile_key, conn_timeout=10)
        output = conn.send_command(command)
        if "Invalid input" in output:
             output = conn.send_command('display interface brief')
             profile_key = 'huawei_switch' 
        return parse_interfaces(output, profile_key)
    except Exception as e:
        print(f"Falha ao buscar interfaces: {e}")
        return [f"ERRO: {e}"]
    finally:
        if conn: conn.disconnect()