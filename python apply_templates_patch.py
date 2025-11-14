#!/usr/bin/env python3
# apply_templates_patch.py
# Use este script para aplicar os templates e patches no projeto "Redes Cencosud".
# Faça um backup do diretório antes de rodar por precaução.

import os, shutil, textwrap, zipfile, sys

BASE = os.path.join(os.getcwd(), "Redes Cencosud")
if not os.path.isdir(BASE):
    print("Erro: não achei o diretório 'Redes Cencosud' no diretório atual.")
    sys.exit(1)

def backup_file(path):
    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copy(path, bak)
        print("Backup criado:", bak)
    else:
        print("Backup já existe:", bak)

# 1) Append helper functions to api_clients.py
api_path = os.path.join(BASE, "api_clients.py")
if os.path.exists(api_path):
    backup_file(api_path)
    with open(api_path, "r", encoding="utf-8") as f:
        api_txt = f.read()
else:
    api_txt = ""
    print("Aviso: api_clients.py não encontrado -- criando novo.")

helpers = textwrap.dedent(r"""
# ------------------ ADICIONADO: Execução de blocos show/config com Netmiko ------------------
try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
except Exception:
    ConnectHandler = None
    NetmikoTimeoutException = Exception
    NetmikoAuthenticationException = Exception

import datetime, os, re
from concurrent.futures import ThreadPoolExecutor

def expand_interface_list(iface_str):
    out = []
    if not iface_str:
        return out
    parts = re.split(r'\s*,\s*', iface_str.strip())
    for p in parts:
        p = p.strip()
        if not p:
            continue
        # Fa0/1-3 handling
        if '/' in p and '-' in p:
            base, rng = p.rsplit('/', 1)
            if '-' in rng:
                start, end = rng.split('-', 1)
                try:
                    for i in range(int(start), int(end)+1):
                        out.append(f"{base}/{i}")
                    continue
                except:
                    pass
        # Gi1-3 style
        m = re.match(r'([A-Za-z]+)(\d+)-(\d+)$', p)
        if m:
            name = m.group(1)
            start = int(m.group(2)); end = int(m.group(3))
            for i in range(start, end+1):
                out.append(f"{name}{i}")
            continue
        out.append(p)
    return out

def save_config_backup(output, host, folder="backups"):
    os.makedirs(folder, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(folder, f"{host}_{ts}.cfg")
    with open(fname, "w", encoding="utf-8") as f:
        f.write(output)
    return fname

def open_connection_netmiko(host, username, password, vendor=None, port=22, secret=None, conn_timeout=30):
    if ConnectHandler is None:
        raise RuntimeError("Netmiko não está instalado. Instale 'netmiko' para usar este executor.")
    device_type_map = {
        'cisco': 'cisco_ios',
        'cisco_ios': 'cisco_ios',
        'fortios': 'fortios',
        'fortinet': 'fortios',
        'huawei': 'huawei',
    }
    device_type = device_type_map.get((vendor or '').lower(), 'cisco_ios')
    conn_params = {
        'device_type': device_type,
        'host': host,
        'username': username,
        'password': password,
        'port': port,
        'timeout': conn_timeout,
    }
    if secret:
        conn_params['secret'] = secret
    return ConnectHandler(**conn_params)

def execute_commands(host, username, password, vendor=None,
                     show_commands=None, config_commands=None,
                     port=22, secret=None, timeout=30, save_backup=True, do_write=False):
    result = {'host': host, 'show': {}, 'config': {}, 'errors': [], 'backup_file': None}
    show_commands = show_commands or []
    config_commands = config_commands or []

    if ConnectHandler is None:
        result['errors'].append("Netmiko não disponível.")
        return result

    try:
        conn = open_connection_netmiko(host, username, password, vendor=vendor, port=port, secret=secret, conn_timeout=timeout)
    except Exception as e:
        result['errors'].append(f"Conexão falhou: {e}")
        return result

    try:
        # simple vendor detection
        if not vendor:
            try:
                ver = conn.send_command("show version")
                if 'Forti' in ver or 'FortiGate' in ver: vendor = 'fortios'
                elif 'Huawei' in ver or 'VRP' in ver: vendor = 'huawei'
                else: vendor = 'cisco'
            except:
                vendor = 'cisco'

        # backup
        try:
            if vendor.startswith('cisco'):
                backup_out = conn.send_command("show running-config")
            elif vendor.startswith('fort'):
                backup_out = conn.send_command("show full-configuration")
            elif vendor.startswith('hua'):
                backup_out = conn.send_command("display current-configuration")
            else:
                backup_out = conn.send_command("show running-config")
            if save_backup:
                result['backup_file'] = save_config_backup(backup_out, host)
        except Exception as e:
            result['errors'].append(f"Backup falhou: {e}")

        # shows
        for cmd in show_commands:
            try:
                out = conn.send_command(cmd)
                result['show'][cmd] = out
            except Exception as e:
                result['show'][cmd] = f"ERROR: {e}"
                result['errors'].append(f"Show cmd error [{cmd}]: {e}")

        # config
        if config_commands:
            try:
                out = conn.send_config_set(config_commands, exit_config_mode=True)
                result['config']['__block__'] = out
                if do_write:
                    try:
                        if vendor.startswith('cisco'):
                            save_out = conn.send_command("write memory")
                        elif vendor.startswith('fort'):
                            save_out = conn.send_command("execute config-save")
                        elif vendor.startswith('hua'):
                            save_out = conn.send_command("save force")
                        else:
                            save_out = ""
                        result['config']['__save__'] = save_out
                    except Exception as e:
                        result['errors'].append(f"Falha ao salvar config: {e}")
            except Exception as e:
                result['errors'].append(f"Erro ao aplicar config: {e}")
                result['config']['__error__'] = str(e)

    finally:
        try:
            conn.disconnect()
        except:
            pass

    return result

def execute_bulk(devices, max_workers=10):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        for d in devices:
            futures.append(ex.submit(execute_commands,
                                     d.get('host'), d.get('username'), d.get('password'),
                                     d.get('vendor'),
                                     d.get('show_commands', []), d.get('config_commands', []),
                                     d.get('port', 22), d.get('secret'),
                                     d.get('timeout', 30), d.get('save_backup', True), d.get('do_write', False)))
        for f in futures:
            results.append(f.result())
    return results

def restore_backup(host, username, password, backup_file, vendor=None, port=22, secret=None, timeout=30):
    result = {'host': host, 'applied_lines': 0, 'errors': [], 'backup_file': backup_file}
    if ConnectHandler is None:
        result['errors'].append('Netmiko não disponível.')
        return result
    if not os.path.exists(backup_file):
        result['errors'].append('Arquivo de backup não encontrado.')
        return result
    with open(backup_file, 'r', encoding='utf-8') as f:
        lines = [l.rstrip() for l in f.readlines() if l.strip()]
    try:
        conn = open_connection_netmiko(host, username, password, vendor=vendor, port=port, secret=secret, conn_timeout=timeout)
    except Exception as e:
        result['errors'].append(f'Falha conexão: {e}')
        return result
    try:
        out = conn.send_config_set(lines, exit_config_mode=True)
        result['applied_lines'] = len(lines)
        result['output'] = out
    except Exception as e:
        result['errors'].append(str(e))
    finally:
        try:
            conn.disconnect()
        except:
            pass
    return result
# ------------------ FIM ADIÇÃO ------------------
""")

    # Append or create file
if api_txt.strip():
    if "ADICIONADO: Execução de blocos" not in api_txt:
        with open(api_path, "a", encoding="utf-8") as f:
            f.write("\n\n" + helpers)
        print("helpers appended to api_clients.py")
    else:
        print("helpers already present in api_clients.py (skipping)")
else:
    with open(api_path, "w", encoding="utf-8") as f:
        f.write("# api_clients.py (criado pelo script)\n\n" + helpers)
    print("api_clients.py criado com helpers")

# 2) Create ssh_runner.py (new runner that uses execute_commands)
ssh_runner_path = os.path.join(BASE, "ssh_runner.py")
if not os.path.exists(ssh_runner_path):
    runner_code = textwrap.dedent(r'''
    import tkinter as tk
    from tkinter import ttk, scrolledtext
    import queue, threading
    from api_clients import SSHClient, execute_commands, restore_backup

    class SSHOutputWindow(tk.Toplevel):
        def __init__(self, parent, host_ip, ssh_user, ssh_pass, commands):
            super().__init__(parent)
            self.title(f"Saída SSH - {host_ip}")
            self.geometry("900x500")
            self.host = host_ip
            self.user = ssh_user
            self.password = ssh_pass
            self.commands = commands
            self.last_backup = None

            self.log_queue = queue.Queue()
            # UI
            log_frame = ttk.Frame(self, padding="5")
            log_frame.pack(fill=tk.BOTH, expand=True)
            self.text_widget = scrolledtext.ScrolledText(log_frame, state='normal')
            self.text_widget.pack(fill=tk.BOTH, expand=True)

            btn_frame = ttk.Frame(self)
            btn_frame.pack(fill=tk.X, pady=4)
            ttk.Button(btn_frame, text="Fechar", command=self.on_close).pack(side=tk.RIGHT, padx=6)
            self.rollback_btn = ttk.Button(btn_frame, text="Rollback (aplicar backup)", command=self.do_rollback, state='disabled')
            self.rollback_btn.pack(side=tk.RIGHT, padx=6)

            t = threading.Thread(target=self.worker_thread, daemon=True)
            t.start()
            self.check_ssh_queue()

        def log_message(self, message):
            self.text_widget.configure(state='normal')
            self.text_widget.insert('end', message + '\\n')
            self.text_widget.see('end')
            self.text_widget.configure(state='disabled')

        def worker_thread(self):
            try:
                self.log_queue.put(f"--- Conectando em {self.host} ---")
                if isinstance(self.commands, dict):
                    payload = self.commands
                    host = self.host; user = self.user; pwd = self.password
                    vendor = payload.get('vendor')
                    show_cmds = payload.get('show', [])
                    config_cmds = payload.get('config', [])
                    do_write = payload.get('do_write', False)
                    save_backup = payload.get('save_backup', True)
                    res = execute_commands(host, user, pwd, vendor=vendor,
                                           show_commands=show_cmds, config_commands=config_cmds,
                                           do_write=do_write, save_backup=save_backup)
                    if res.get('backup_file'):
                        self.last_backup = res.get('backup_file')
                        self.log_queue.put(f"Backup salvo: {res['backup_file']}")
                        try:
                            self.rollback_btn.configure(state='normal')
                        except:
                            pass
                    for cmd, out in res.get('show', {}).items():
                        self.log_queue.put(f">>> SHOW: {cmd}\\n{out}")
                    if res.get('config'):
                        self.log_queue.put(">>> CONFIG RESULT:")
                        self.log_queue.put(res.get('config').get('__block__',''))
                        if '__save__' in res.get('config'):
                            self.log_queue.put('SAVE OUTPUT:\\n' + res.get('config').get('__save__',''))
                    if res.get('errors'):
                        self.log_queue.put('ERROS:\\n' + '\\n'.join(res['errors']))
                    self.log_queue.put(None)
                    return
                else:
                    client = SSHClient()
                    try:
                        client.connect(self.host, username=self.user, password=self.password, timeout=10, look_for_keys=False, allow_agent=False)
                        for desc, cmd in self.commands:
                            self.log_queue.put(f"--- CMD: {desc} ({cmd}) ---")
                            try:
                                out = client.exec_command(cmd)
                                self.log_queue.put(out)
                            except Exception as e:
                                self.log_queue.put(f"ERROR executing {cmd}: {e}")
                    except Exception as e:
                        self.log_queue.put(f"SSH conexão/exec error: {e}")
                    finally:
                        try:
                            client.close()
                        except:
                            pass
                    self.log_queue.put(None)
                    return
            except Exception as e:
                self.log_queue.put(f"Worker fail: {e}")
                self.log_queue.put(None)
                return

        def check_ssh_queue(self):
            try:
                while True:
                    line = self.log_queue.get_nowait()
                    if line is None:
                        self.log_message("--- Execução SSH concluída ---")
                        return
                    else:
                        self.log_message(line)
            except queue.Empty:
                pass
            self.after(100, self.check_ssh_queue)

        def do_rollback(self):
            if not self.last_backup:
                self.log_queue.put("Nenhum backup disponível para rollback.")
                return
            self.log_queue.put(f"Iniciando rollback aplicando {self.last_backup} ...")
            res = restore_backup(self.host, self.user, self.password, self.last_backup)
            if res.get('errors'):
                self.log_queue.put('Erros no rollback:\\n' + '\\n'.join(res['errors']))
            else:
                self.log_queue.put(f'Rollback aplicado (linhas: {res.get(\"applied_lines\")})')
        def on_close(self):
            try:
                self.destroy()
            except:
                pass
    ''')
    with open(ssh_runner_path, "w", encoding="utf-8") as f:
        f.write(runner_code)
    print("ssh_runner.py criado.")
else:
    print("ssh_runner.py já existe; não sobrescrevi.")

# 3) Insert TEMPLATES dict into main_app.py and add selectors in dialog
main_path = os.path.join(BASE, "main_app.py")
if os.path.exists(main_path):
    backup_file(main_path)
    with open(main_path, "r", encoding="utf-8") as f:
        main_txt = f.read()
    # Add templates near top (after imports)
    templates_block = textwrap.dedent("""
    # --- Templates pré-carregados para o diálogo avançado ---
    TEMPLATES = {
        'Cisco': {
            'SNMP': {'show': [], 'config': ['conf t','snmp-server community e28a7a3e RO','snmp ifmib ifindex persist','end']},
            'TACACS': {'show': [], 'config': ['conf t','aaa new-model','aaa authentication login default group tacacs+ local','aaa authorization exec default group tacacs+ local','end']},
            'VLANs': {'show': [], 'config': ['conf t','vlan 11\\n name VLAN0011\\nexit','vlan 12\\n name VLAN0012\\nexit','end']}
        },
        'FortiSwitch': {
            'Interfaces - PC': {'show': [], 'config': ['config switch interface','edit {INTERFACE}',' set native-vlan 81',' set allowed-vlans 50','next','end']},
            'VLANs': {'show': [], 'config': ['config switch vlan',' edit 100','  set description \"VLAN_MGMT\"',' next','end']},
        },
        'Huawei': {
            'PC VLAN 80': {'show': [], 'config': ['system-view','interface {INTERFACE}',' description PC',' port default vlan 80','return']},
            'PC VLAN 81': {'show': [], 'config': ['system-view','interface {INTERFACE}',' description PC',' port default vlan 81','return']},
            'CFTV VLAN 75': {'show': [], 'config': ['system-view','interface {INTERFACE}',' description CFTV',' port default vlan 75','return']},
            'AP trunk native 100': {'show': [], 'config': ['system-view','interface {INTERFACE}',' description {AP_NAME}',' port link-type trunk',' port trunk pvid vlan 100',' port trunk allow-pass vlan all','return']},
            'Create VLANs (full list)': {'show': [], 'config': ['system-view','vlan 9\\n name WIFI-Temporario','vlan 10\\n name WiFiGer','vlan 11\\n name CSWLAN11','vlan 12\\n name CSWLAN12','vlan 15\\n name CSWLAN15','vlan 16\\n name Clientes_Cencosud','vlan 50\\n name VOIP','vlan 75\\n name CFTV','vlan 80\\n name PC','vlan 81\\n name PC_2','vlan 95\\n name PDV','vlan 100\\n name Management','return']},
            'Create VLAN (single)': {'show': [], 'config': ['system-view','vlan {VLAN_ID}',' name {VLAN_NAME}','return']}
        }
    }
    # --- end templates ---
    """)
    # insert after first occurrence of "import webbrowser" or at top
    marker = "import webbrowser"
    pos = main_txt.find(marker)
    if pos != -1:
        nl = main_txt.find("\n", pos)
        main_txt = main_txt[:nl+1] + templates_block + main_txt[nl+1:]
    else:
        main_txt = templates_block + main_txt

    # Add template selectors inside open_advanced_commands_dialog (simple approach: replace the known pattern)
    if "def open_advanced_commands_dialog" in main_txt and "vendor_box = ttk.Combobox" not in main_txt:
        main_txt = main_txt.replace(
            "ttk.Label(frm, text=\"Config commands (uma por linha):\").pack(anchor=tk.W)\n        config_txt = tk.Text(frm, height=12)\n        config_txt.pack(fill=tk.X, pady=4)\n\n        iface_frame = ttk.Frame(frm)",
            "ttk.Label(frm, text=\"Config commands (uma por linha):\").pack(anchor=tk.W)\n        config_txt = tk.Text(frm, height=12)\n        config_txt.pack(fill=tk.X, pady=4)\n\n        sel_frame = ttk.Frame(frm)\n        sel_frame.pack(fill=tk.X, pady=4)\n        ttk.Label(sel_frame, text='Fornecedor:').pack(side=tk.LEFT)\n        vendor_choice = tk.StringVar()\n        vendor_box = ttk.Combobox(sel_frame, textvariable=vendor_choice, state='readonly')\n        vendor_box['values'] = list(TEMPLATES.keys())\n        vendor_box.pack(side=tk.LEFT, padx=6)\n        ttk.Label(sel_frame, text='Template:').pack(side=tk.LEFT, padx=(10,0))\n        template_choice = tk.StringVar()\n        template_box = ttk.Combobox(sel_frame, textvariable=template_choice, state='readonly')\n        template_box.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)\n\n        def on_vendor_selected(event=None):\n            v = vendor_choice.get()\n            if not v or v not in TEMPLATES:\n                template_box['values']=[]\n                template_box.set('')\n                return\n            template_box['values'] = list(TEMPLATES[v].keys())\n            template_box.set('')\n\n        def on_template_selected(event=None):\n            v = vendor_choice.get(); t = template_choice.get()\n            if not v or not t: return\n            tpl = TEMPLATES.get(v, {}).get(t, {})\n            show_lines = tpl.get('show', [])\n            config_lines = tpl.get('config', [])\n            show_txt.delete('1.0','end'); config_txt.delete('1.0','end')\n            if show_lines:\n                show_txt.insert('1.0', '\\n'.join(show_lines))\n            if config_lines:\n                config_txt.insert('1.0', '\\n'.join(config_lines))\n\n        vendor_box.bind('<<ComboboxSelected>>', on_vendor_selected)\n        template_box.bind('<<ComboboxSelected>>', on_template_selected)\n\n        iface_frame = ttk.Frame(frm)"
        )
    with open(main_path, "w", encoding="utf-8") as f:
        f.write(main_txt)
    print("main_app.py atualizado com templates e selectors.")
else:
    print("main_app.py não encontrado; pulei a modificação do main_app.")

# 4) Create ZIP of modified project
out_zip = os.path.join(os.getcwd(), "Redes_Cencosud_modified_with_templates.zip")
with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(BASE):
        for file in files:
            full = os.path.join(root, file)
            arc = os.path.relpath(full, os.path.join(os.path.dirname(BASE)))
            z.write(full, arc)
print("ZIP criado:", out_zip)
print("Pronto. Verifique os arquivos modificados e teste o app. Não esqueça de instalar netmiko: pip install netmiko")
