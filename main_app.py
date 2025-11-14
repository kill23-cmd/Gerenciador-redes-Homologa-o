# main_app.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import config_manager
from settings_window import SettingsWindow
from api_clients import ZabbixClient
from ssh_runner import SSHOutputWindow
import webbrowser
import subprocess
import threading 

# (COMMAND_PROFILES e VENDOR_CONFIG_SNIPPETS continuam os mesmos)
# --- DEFINIÇÃO DOS PERFIS DE COMANDOS (SHOW) ---
COMMAND_PROFILES = {
    'cisco_router': [
        ('Mostrar interfaces (brief)', 'show ip interface brief'),
        ('Mostrar vizinhos CDP', 'show cdp neighbors'),
        ('Mostrar config (running)', 'show running-config'),
        ('Mostrar pools DHCP', 'show ip dhcp pool'),
        ('Mostrar tabela ARP', 'show ip arp')
    ],
    'cisco_switch': [
        ('Mostrar interfaces (brief)', 'show ip interface brief'),
        ('Mostrar vizinhos CDP', 'show cdp neighbors'),
        ('Mostrar config (running)', 'show running-config'),
        ('Mostrar consumo PoE', 'show power inline'),
        ('Mostrar descrição interfaces', 'show interfaces description'),
        ('Mostrar status interfaces', 'show interfaces status'),
        ('Mostrar vizinhos LLDP', 'show lldp neighbors'),
        ('Mostrar VLANs', 'show vlan brief'),
        ('Mostrar interfaces Trunk', 'show interfaces trunk'),
        ('Mostrar tabela MAC', 'show mac address-table'),
        ('Mostrar contadores de erros', 'show interfaces counters errors')
    ],
    'fortinet_firewall': [
        ('Mostrar tabela ARP', 'get sys arp'),
        ('Mostrar ARP (WAN)', 'get sys arp | grep wan'),
        ('Listar túneis IPsec', 'get vpn ipsec tunnel list'),
        ('Sumário túneis IPsec', 'get vpn ipsec tunnel summary'),
        ('Sumário BGP', 'get router info bgp summary'),
        ('Mostrar DHCP Server', 'show sys dhcp server'),
        ('Mostrar status sistema', 'get sys status'),
        ('Mostrar Performance SLA', 'diagnose sys sdwan health-check'),
        ('Mostrar interfaces (WAN)', 'get sys interface | grep wan'),
        ('Mostrar quantidade de sessões', 'get system session status'),
        ('Limpar todas as sessões', 'diagnose sys session clear')
    ],
    'fortiswitch': [
        ('Mostrar vizinhos LLDP', 'get switch lldp neighbors-summary'),
        ('Mostrar consumo PoE', 'get switch poe inline'),
        ('Mostrar configuração das interfaces', 'show switch interface'),
        ('Mostar VLANs', 'diagnose switch vlan list'),
        ('Mostrar status interfaces', 'diagnose switch physical-ports summary'),
        ('Mostrar contatdores de erros', 'diag switch physical-ports port-stats list')
    ],
    'huawei_switch': [
        ('Mostrar vizinhos LLDP', 'display lldp ne brief')
    ],
    'default': [] # Perfil padrão, sem comandos
}

# --- DEFINIÇÃO DOS SNIPPETS DE CONFIGURAÇÃO POR VENDOR ---
VENDOR_CONFIG_SNIPPETS = {
    'huawei_switch': {
        "Template: Criar VLAN": "vlan 99\n name NOME_DA_VLAN\n quit",
        "Template: Interface PC (VLAN 80)": "interface {INTERFACE}\n description PC\n port default vlan 80\n quit",
    },
    'cisco_switch': {
        "Configurar SNMP": "snmp-server community e28a7a3e RO\nsnmp ifmib ifindex persist",
        "Template: Interface PC (VLAN 81+50)": (
            "interface {INTERFACE}\n"
            " switchport access vlan 81\n"
            " switchport voice vlan 50\n"
            " spanning-tree portfast"
        ),
    },
    'fortiswitch': {
        "Template: Interface PC": (
            "config switch interface\n"
            " edit {INTERFACE}\n"
            "  set native-vlan 81\n"
            "  set allowed-vlans 50\n"
            " next\n"
            "end"
        ),
    },
    'cisco_router': {},
    'fortinet_firewall': {},
    'default': {}
}


# --- ATUALIZADO: Termos de Busca (Híbrido) ---
# 1. Busca por CHAVES (Padrão e universal)
ZABBIX_DASHBOARD_KEY_SEARCH = [
    "system.uptime",
    "icmpping",
    "icmppingloss",
    "system.cpu.util"
]
# 2. Busca por NOMES (Específico do equipamento)
ZABBIX_DASHBOARD_NAME_SEARCH = [
    # Itens de Switch/Router (NOMES)
    "Number of interfaces in operational state down",
    
    # Itens de Firewall (NOMES)
    "wan1", # Busca todos os itens que contenham "wan1"
    "wan2"  # Busca todos os itens que contenham "wan2"
]
# ----------------------------------------------------


class MainApplication(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Gerenciador Remoto Zabbix")
        self.geometry("800x700") 

        self.zabbix_client = None
        self.settings = None 
        self.hostgroups_map = {} 
        self.hosts_data_map = {} 
        self.command_vars = []
        
        self.current_selected_hostid = None
        
        self.dash_name_vars = {
            'L1_name': tk.StringVar(value="--"), 'R1_name': tk.StringVar(value="--"),
            'L2_name': tk.StringVar(value="--"), 'R2_name': tk.StringVar(value="--"),
            'L3_name': tk.StringVar(value="--"), 'R3_name': tk.StringVar(value="--"),
            'L4_name': tk.StringVar(value="--"), 'R4_name': tk.StringVar(value="--"),
        }
        self.dash_value_vars = {
            'uptime': tk.StringVar(value="--"), 'latency': tk.StringVar(value="--"),
            'loss': tk.StringVar(value="--"), 'cpu': tk.StringVar(value="--"),
            'L1_val': tk.StringVar(value="--"), 'R1_val': tk.StringVar(value="--"),
            'L2_val': tk.StringVar(value="--"), 'R2_val': tk.StringVar(value="--"),
            'L3_val': tk.StringVar(value="--"), 'R3_val': tk.StringVar(value="--"),
            'L4_val': tk.StringVar(value="--"), 'R4_val': tk.StringVar(value="--"),
        }
        self.dash_value_labels = {}
        
        # --- Bloco de Estilo (Corrigido para Compatibilidade) ---
        s = ttk.Style()
        try:
            default_bg = s.lookup('TFrame', 'background')
            s.configure('Problem.TLabel', foreground='red')
            s.configure('NoProblem.TLabel', foreground='green')
            s.configure('Problem.TButton', foreground='red', font=('TkDefaultFont', 9, 'underline'), anchor='w', borderwidth=0, padding=0)
            s.configure('NoProblem.TButton', foreground='green', font=('TkDefaultFont', 9), anchor='w', borderwidth=0, padding=0)
            s.map('Problem.TButton',
                  background=[('active', default_bg), ('!active', default_bg)],
                  bordercolor=[('active', default_bg), ('!active', default_bg)],
                  lightcolor=[('active', default_bg), ('!active', default_bg)],
                  darkcolor=[('active', default_bg), ('!active', default_bg)]
            )
            s.map('NoProblem.TButton',
                  background=[('active', default_bg), ('!active', default_bg)],
                  bordercolor=[('active', default_bg), ('!active', default_bg)],
                  lightcolor=[('active', default_bg), ('!active', default_bg)],
                  darkcolor=[('active', default_bg), ('!active', default_bg)]
            )
        except Exception as e:
            print(f"Aviso: Não foi possível aplicar estilos avançados: {e}")
            s.configure('Problem.TButton', foreground='red', font=('TkDefaultFont', 9, 'underline'))
            s.configure('NoProblem.TButton', foreground='green', font=('TkDefaultFont', 9))
        # --- FIM DO BLOCO DE ESTILO ---


        self.create_menu()
        self.create_widgets()
        
        self.load_config_and_connect()

    def create_menu(self):
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)
        
        menu_opcoes = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Opções", menu=menu_opcoes)
        menu_opcoes.add_command(label="Configurações", command=self.open_settings)
        menu_opcoes.add_separator()
        menu_opcoes.add_command(label="Sair", command=self.quit)

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        left_panel = ttk.Frame(main_frame, width=350)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        loja_frame = ttk.Labelframe(left_panel, text="Loja") 
        loja_frame.pack(fill=tk.X, pady=5)
        
        self.cb_loja = ttk.Combobox(loja_frame, state="readonly")
        self.cb_loja.pack(fill=tk.X, expand=True, padx=5, pady=5)
        self.cb_loja.bind("<<ComboboxSelected>>", self.on_hostgroup_select)

        pdv_frame = ttk.Labelframe(left_panel, text="Hosts")
        pdv_frame.pack(fill=tk.X, pady=5)
        
        self.lb_hosts = tk.Listbox(pdv_frame, selectmode=tk.EXTENDED, height=6)
        self.lb_hosts.pack(fill=tk.X, expand=True, padx=5, pady=5)
        self.lb_hosts.bind("<<ListboxSelect>>", self.on_host_select)
        sb = ttk.Scrollbar(pdv_frame, orient=tk.VERTICAL, command=self.lb_hosts.yview)
        self.lb_hosts.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        
        # --- Painel de Status (agora 100% dinâmico) ---
        self.dashboard_frame = ttk.Labelframe(left_panel, text="Host Status (Zabbix)")
        self.dashboard_frame.pack(fill=tk.X, pady=(10, 5))
        
        dash_grid = ttk.Frame(self.dashboard_frame, padding=5)
        dash_grid.pack(fill=tk.X)
        dash_grid.columnconfigure(1, weight=1)
        dash_grid.columnconfigure(3, weight=1)
        
        # --- Métricas Base (Estáticas) ---
        ttk.Label(dash_grid, text="Disponibilidade:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(dash_grid, textvariable=self.dash_value_vars['uptime']).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(dash_grid, text="CPU:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(dash_grid, textvariable=self.dash_value_vars['cpu']).grid(row=1, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(dash_grid, text="Latência:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(dash_grid, textvariable=self.dash_value_vars['latency']).grid(row=2, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(dash_grid, text="Perda de Pacotes:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.dash_value_labels['loss'] = ttk.Label(dash_grid, textvariable=self.dash_value_vars['loss'])
        self.dash_value_labels['loss'].grid(row=3, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Separator(dash_grid, orient='horizontal').grid(row=4, column=0, columnspan=4, sticky='ew', pady=5)

        # --- Métricas Dinâmicas (Linha 1) ---
        ttk.Label(dash_grid, textvariable=self.dash_name_vars['L1_name']).grid(row=5, column=0, sticky="w", padx=5, pady=2)
        self.dash_value_labels['L1_val'] = ttk.Button(dash_grid, textvariable=self.dash_value_vars['L1_val'], style="NoProblem.TButton", state="disabled")
        self.dash_value_labels['L1_val'].grid(row=5, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(dash_grid, textvariable=self.dash_name_vars['R1_name']).grid(row=5, column=2, sticky="w", padx=5, pady=2)
        self.dash_value_labels['R1_val'] = ttk.Label(dash_grid, textvariable=self.dash_value_vars['R1_val'])
        self.dash_value_labels['R1_val'].grid(row=5, column=3, sticky="w", padx=5, pady=2)
        
        # --- Métricas Dinâmicas (Linha 2) ---
        ttk.Label(dash_grid, textvariable=self.dash_name_vars['L2_name']).grid(row=6, column=0, sticky="w", padx=5, pady=2)
        self.dash_value_labels['L2_val'] = ttk.Label(dash_grid, textvariable=self.dash_value_vars['L2_val'])
        self.dash_value_labels['L2_val'].grid(row=6, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(dash_grid, textvariable=self.dash_name_vars['R2_name']).grid(row=6, column=2, sticky="w", padx=5, pady=2)
        self.dash_value_labels['R2_val'] = ttk.Label(dash_grid, textvariable=self.dash_value_vars['R2_val'])
        self.dash_value_labels['R2_val'].grid(row=6, column=3, sticky="w", padx=5, pady=2)
        
        # --- Métricas Dinâmicas (Linha 3) ---
        ttk.Label(dash_grid, textvariable=self.dash_name_vars['L3_name']).grid(row=7, column=0, sticky="w", padx=5, pady=2)
        self.dash_value_labels['L3_val'] = ttk.Label(dash_grid, textvariable=self.dash_value_vars['L3_val'])
        self.dash_value_labels['L3_val'].grid(row=7, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(dash_grid, textvariable=self.dash_name_vars['R3_name']).grid(row=7, column=2, sticky="w", padx=5, pady=2)
        self.dash_value_labels['R3_val'] = ttk.Label(dash_grid, textvariable=self.dash_value_vars['R3_val'])
        self.dash_value_labels['R3_val'].grid(row=7, column=3, sticky="w", padx=5, pady=2)
        
        # --- Métricas Dinâmicas (Linha 4) ---
        ttk.Label(dash_grid, textvariable=self.dash_name_vars['L4_name']).grid(row=8, column=0, sticky="w", padx=5, pady=2)
        self.dash_value_labels['L4_val'] = ttk.Label(dash_grid, textvariable=self.dash_value_vars['L4_val'])
        self.dash_value_labels['L4_val'].grid(row=8, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(dash_grid, textvariable=self.dash_name_vars['R4_name']).grid(row=8, column=2, sticky="w", padx=5, pady=2)
        self.dash_value_labels['R4_val'] = ttk.Label(dash_grid, textvariable=self.dash_value_vars['R4_val'])
        self.dash_value_labels['R4_val'].grid(row=8, column=3, sticky="w", padx=5, pady=2)
        # --- FIM DO PAINEL ---

        self.action_button_frame = ttk.Frame(left_panel)
        self.action_button_frame.pack(fill=tk.X, pady=(5,0))

        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)

        self.cmd_frame = ttk.Labelframe(right_panel, text="Comandos Remotos (Simples)")
        self.cmd_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.btn_executar_simples = ttk.Button(right_panel, text="Executar Comandos Selecionados", command=self.run_simple_ssh)
        self.btn_executar_simples.pack(pady=(10, 5), fill=tk.X)

        self.btn_config_avancada = ttk.Button(right_panel, text="Configuração Avançada...", command=self.open_advanced_ssh_dialog)
        self.btn_config_avancada.pack(pady=(0, 10), fill=tk.X)

    def select_all_commands(self):
        for var, _, _ in self.command_vars:
            var.set(True)
    
    def deselect_all_commands(self):
        for var, _, _ in self.command_vars:
            var.set(False)

    def open_settings(self):
        SettingsWindow(self, self.settings, save_callback=self.on_settings_saved)

    def on_settings_saved(self):
        print("Configurações salvas. Tentando reconectar...")
        self.load_config_and_connect()

    def load_config_and_connect(self):
        self.settings = config_manager.load_settings()
        
        if not self.settings:
            print("Configurações não encontradas. Aguardando usuário...")
            return
        
        try:
            print(f"Conectando ao Zabbix em {self.settings['zabbix_url']}...")
            self.zabbix_client = ZabbixClient(
                self.settings['zabbix_url'],
                self.settings['zabbix_user'],
                self.settings['zabbix_pass']
            )
            self.populate_hostgroups()
            print("Conectado ao Zabbix com sucesso.")
            
        except Exception as e:
            messagebox.showerror("Erro de Conexão Zabbix", 
                                 f"Não foi possível conectar ao Zabbix. Verifique as 'Opções'.\nErro: {e}")

    def populate_hostgroups(self):
        if not self.zabbix_client:
            print("Cliente Zabbix não inicializado.")
            return
        
        hostgroups = self.zabbix_client.get_hostgroups()
        self.hostgroups_map = {group['name']: group['groupid'] for group in hostgroups}
        self.cb_loja['values'] = sorted(self.hostgroups_map.keys())
        
        self.lb_hosts.delete(0, tk.END)
        print("Grupos de hosts carregados.")

    def on_hostgroup_select(self, event):
        selected_group_name = self.cb_loja.get()
        group_id = self.hostgroups_map.get(selected_group_name)
        
        if not group_id:
            return
            
        hosts = self.zabbix_client.get_hosts_by_groupid(group_id)
        
        self.hosts_data_map.clear()
        host_list_strings = []
        
        for h in hosts:
            host_ip_to_display = h['host'] 
            
            if h.get('interfaces'):
                main_interface = next((iface for iface in h['interfaces'] if iface['main'] == '1'), None)
                if main_interface:
                    host_ip_to_display = main_interface['ip']
                elif h['interfaces']:
                    host_ip_to_display = h['interfaces'][0]['ip']
            
            h['actual_ip'] = host_ip_to_display
            
            display_string = f"{h['name']} - {host_ip_to_display}"
            host_list_strings.append(display_string)
            self.hosts_data_map[display_string] = h 
            
        self.lb_hosts.delete(0, tk.END)
        for hstr in sorted(host_list_strings):
            self.lb_hosts.insert(tk.END, hstr)
            
        self.lb_hosts.selection_clear(0, tk.END)
        self.populate_commands_frame('default')
        self.update_action_buttons('default')
        self.clear_dashboard()

        
    def on_host_select(self, event):
        sel_idxs = self.lb_hosts.curselection()
        if not sel_idxs:
            self.populate_commands_frame('default')
            self.update_action_buttons('default')
            self.clear_dashboard() 
            return

        first = self.lb_hosts.get(sel_idxs[0])
        host_data = self.hosts_data_map.get(first)
        if not host_data:
            self.populate_commands_frame('default')
            self.update_action_buttons('default')
            self.clear_dashboard()
            return

        inventory = host_data.get('inventory', {})
        os_field = inventory.get('os', '').lower()
        hardware_field = inventory.get('hardware', '').lower()
        hostname = host_data.get('name', '').lower()

        profile_key = self.determine_command_profile(os_field, hardware_field, hostname)
        self.populate_commands_frame(profile_key)
        self.update_action_buttons(profile_key)
        
        for k, v in self.dash_value_vars.items():
            v.set("Buscando...")
        self.clear_dashboard_names() # Limpa os nomes também
        
        host_id = host_data.get('hostid')
        self.current_selected_hostid = host_id # Salva o ID para o botão de problemas
        
        if host_id:
            # Passa o profile_key para o thread de busca
            threading.Thread(target=self.fetch_dashboard_data, args=(host_id, profile_key), daemon=True).start()

    # --- ATUALIZADO: Funções do Dashboard (Lógica Híbrida) ---
    def fetch_dashboard_data(self, host_id, profile_key):
        """(Executado em Thread) Busca dados do Zabbix."""
        if not self.zabbix_client:
            return
        
        try:
            # 1. Busca os itens padrão (por Chave)
            key_data = self.zabbix_client.get_host_items_by_key(
                host_id, 
                ZABBIX_DASHBOARD_KEY_SEARCH
            )
            
            # 2. Busca os itens de interface (por Nomes)
            name_data = self.zabbix_client.get_host_items_by_name(
                host_id, 
                ZABBIX_DASHBOARD_NAME_SEARCH
            )
            
            # 3. Busca o número de problemas (Triggers)
            problem_count = self.zabbix_client.get_host_problems_count(host_id)
            
            # 4. Envia os dados e o profile_key para a UI thread
            self.after(0, self.update_dashboard_ui, key_data, name_data, problem_count, profile_key)
            
        except Exception as e:
            print(f"Erro no thread do dashboard: {e}")
            self.after(0, self.clear_dashboard) 

    def update_dashboard_ui(self, key_data, name_data, problem_count, profile_key):
        """(Executado na UI Thread) Atualiza os labels do dashboard."""
        
        # --- Helper para encontrar o item certo na lista ---
        def find_item_by_parts(data_dict, parts_list):
            for name, item_data in data_dict.items():
                name_lower = name.lower()
                parts_lower = [part.lower() for part in parts_list]
                if all(part in name_lower for part in parts_lower):
                    item_data['name'] = name 
                    return item_data 
            return None 

        # --- Helper para buscar valor por chave ---
        def get_value_from_key(data_dict, key_prefix, default='N/A'):
            """Busca um valor no dicionário de chaves (key_data)."""
            for full_key, item_data in data_dict.items():
                if full_key.startswith(key_prefix):
                    return item_data.get('value', default)
            return default

        # --- Helper para buscar valor por nome ---
        def get_value(item_data, default='N/A'):
            """Pega o valor de um item já encontrado."""
            if item_data:
                return item_data.get('value', default)
            return default

        # --- Métricas Base (Uptime, CPU, Latência, Perda) ---
        # ⚠️ (Voltamos a usar as CHAVES, que são mais confiáveis)
        uptime_s = get_value_from_key(key_data, 'system.uptime', '0')
        try:
            uptime_val = int(uptime_s)
            d = uptime_val // (3600*24); h = (uptime_val % (3600*24)) // 3600; m = (uptime_val % 3600) // 60
            self.dash_value_vars['uptime'].set(f"{d}d {h}h {m}m")
        except ValueError: self.dash_value_vars['uptime'].set("N/A")

        cpu_val = get_value_from_key(key_data, 'system.cpu.util', '0')
        try:
            self.dash_value_vars['cpu'].set(f"{float(cpu_val):.2f}%")
        except ValueError: self.dash_value_vars['cpu'].set("N/A")
            
        lat_val = get_value_from_key(key_data, 'icmpping', '0')
        try:
            self.dash_value_vars['latency'].set(f"{float(lat_val)*1000:.2f} ms")
        except ValueError: self.dash_value_vars['latency'].set("N/A")

        loss_val = get_value_from_key(key_data, 'icmppingloss', '0')
        try:
            loss_f = float(loss_val)
            self.dash_value_vars['loss'].set(f"{loss_f:.1f}%")
            style = "Problem.TLabel" if loss_f > 1 else "NoProblem.TLabel"
            self.dash_value_labels['loss'].config(style=style)
        except ValueError:
            self.dash_value_vars['loss'].set("N/A")
            self.dash_value_labels['loss'].config(style="TLabel")

        # --- Helpers de Formatação ---
        def set_if_status(var, label_widget, item_data):
            val = get_value(item_data)
            if val == '1':
                var.set("UP"); label_widget.config(style="NoProblem.TLabel")
            elif val == '2':
                var.set("DOWN"); label_widget.config(style="Problem.TLabel")
            else:
                var.set("N/A"); label_widget.config(style="TLabel")

        def set_if_data(var, item_data, is_bits=False):
            if item_data:
                val = item_data.get('value', 'N/A')
                units = item_data.get('units', '')
                item_name = item_data.get('name', '').lower()
                
                if is_bits and val.isdigit():
                    bits = float(val);
                    if bits > 1_000_000_000: val_str = f"{bits/1_000_000_000:.2f} Gbps"
                    elif bits > 1_000_000: val_str = f"{bits/1_000_000:.2f} Mbps"
                    elif bits > 1_000: val_str = f"{bits/1_000:.2f} Kbps"
                    else: val_str = f"{bits:.0f} bps"
                    var.set(val_str)
                elif "speed" in item_name and val.isdigit():
                     bits = float(val)
                     if bits == 1_000_000_000: var.set("1 Gb/s")
                     elif bits == 100_000_000: var.set("100 Mb/s")
                     elif bits == 10_000_000: var.set("10 Mb/s")
                     else: var.set(f"{val} {units}")
                elif "duplex" in item_name and val.isdigit():
                    if val == '3': var.set("Full-Duplex")
                    elif val == '2': var.set("Half-Duplex")
                    else: var.set("Unknown")
                else:
                    var.set(f"{val} {units}")
            else:
                var.set("N/A")
        
        # --- LÓGICA DO PAINEL DINÂMICO ---
        self.clear_dashboard_names() # Limpa o painel dinâmico
        
        if profile_key == 'fortinet_firewall':
            # --- MODO FIREWALL (Mostra WAN1 e WAN2) ---
            self.dash_name_vars['L1_name'].set("WAN1 Status:")
            self.dash_name_vars['R1_name'].set("WAN2 Status:")
            self.dash_name_vars['L2_name'].set("WAN1 Speed:")
            self.dash_name_vars['R2_name'].set("WAN2 Speed:")
            self.dash_name_vars['L3_name'].set("WAN1 Duplex:")
            self.dash_name_vars['R3_name'].set("WAN2 Duplex:")
            self.dash_name_vars['L4_name'].set("WAN1 Download:")
            self.dash_name_vars['R4_name'].set("WAN2 Download:")
            
            # Muda L1 (Problemas) de Botão para Label
            self.dash_value_labels['L1_val'].config(style="TLabel", command="")
            
            # ⚠️ Verifique se os nomes 'Operational status', 'Speed', etc.
            # ⚠️ são os corretos para os seus itens de firewall!
            set_if_status(self.dash_value_vars['L1_val'], self.dash_value_labels['L1_val'], 
                          find_item_by_parts(name_data, ['wan1', 'Operational status']))
            set_if_status(self.dash_value_vars['R1_val'], self.dash_value_labels['R1_val'], 
                          find_item_by_parts(name_data, ['wan2', 'Operational status']))
            set_if_data(self.dash_value_vars['L2_val'], find_item_by_parts(name_data, ['wan1', 'Speed']))
            set_if_data(self.dash_value_vars['R2_val'], find_item_by_parts(name_data, ['wan2', 'Speed']))
            set_if_data(self.dash_value_vars['L3_val'], find_item_by_parts(name_data, ['wan1', 'Duplex status']))
            set_if_data(self.dash_value_vars['R3_val'], find_item_by_parts(name_data, ['wan2', 'Duplex status']))
            set_if_data(self.dash_value_vars['L4_val'], find_item_by_parts(name_data, ['wan1', 'Bits received']), is_bits=True)
            set_if_data(self.dash_value_vars['R4_val'], find_item_by_parts(name_data, ['wan2', 'Bits received']), is_bits=True)

        else:
            # --- MODO SWITCH/ROUTER (Mostra Problemas) ---
            self.dash_name_vars['L1_name'].set("Problemas Ativos:")
            self.dash_name_vars['L2_name'].set("Interfaces Down:")
            
            # 1. Problemas Ativos (Botão Clicável)
            problem_button = self.dash_value_labels['L1_val']
            if problem_count == -1: # Erro
                self.dash_value_vars['L1_val'].set("Erro")
                problem_button.config(style="Problem.TButton", state="disabled", command="")
            elif problem_count > 0:
                self.dash_value_vars['L1_val'].set(f"{problem_count}")
                problem_button.config(style="Problem.TButton", state="normal",
                                      command=self.show_host_problems)
            else:
                self.dash_value_vars['L1_val'].set("0")
                problem_button.config(style="NoProblem.TButton", state="disabled", command="")

            # 2. Interfaces Down (Label)
            if_down_label = self.dash_value_labels['L2_val']
            if_down_item = find_item_by_parts(name_data, ['interfaces', 'down'])
            if_down_val = get_value(if_down_item, '0')
            try:
                count = int(if_down_val)
                self.dash_value_vars['L2_val'].set(f"{count}")
                style = "Problem.TLabel" if count > 0 else "NoProblem.TLabel"
                if_down_label.config(style=style)
            except ValueError:
                self.dash_value_vars['L2_val'].set("N/A")
                if_down_label.config(style="TLabel")

            # Limpa os outros 6 valores
            for k in ['R1_val', 'R2_val', 'L3_val', 'R3_val', 'L4_val', 'R4_val']:
                self.dash_value_vars[k].set("") 

    def clear_dashboard_names(self):
        """Limpa os nomes (rótulos) dinâmicos."""
        for k, v in self.dash_name_vars.items():
            v.set("") 

    def clear_dashboard(self):
        """Limpa os dados do dashboard (valores E nomes)."""
        self.clear_dashboard_names()
        for k, v in self.dash_value_vars.items():
            v.set("--")
        # Reseta os botões/labels para o padrão
        self.dash_value_labels['L1_val'].config(style="NoProblem.TButton", state="disabled", command="")
        self.dash_value_labels['L2_val'].config(style="TLabel")
        self.dash_value_labels['loss'].config(style="TLabel")
        for k in ['R1_val', 'R2_val', 'L3_val', 'R3_val', 'L4_val', 'R4_val']:
            # Garante que todos os labels dinâmicos sejam resetados para o estilo padrão
            if k in self.dash_value_labels:
                self.dash_value_labels[k].config(style="TLabel")
        
    # --- NOVO: Janela Pop-up de Problemas ---
    def show_host_problems(self):
        """Abre uma nova janela para listar os problemas ativos."""
        if not self.current_selected_hostid:
            messagebox.showwarning("Erro", "Nenhum host selecionado.")
            return

        host_id = self.current_selected_hostid
        
        # Cria a janela
        dlg = tk.Toplevel(self)
        dlg.title("Problemas Ativos do Host")
        dlg.geometry("600x300")
        dlg.transient(self)
        dlg.grab_set()
        
        frm = ttk.Frame(dlg, padding=5)
        frm.pack(fill=tk.BOTH, expand=True)
        
        txt = scrolledtext.ScrolledText(frm, wrap=tk.WORD, height=10, width=70)
        txt.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        txt.insert(tk.END, "Buscando lista de problemas...")
        txt.config(state="disabled")
        
        btn_close = ttk.Button(frm, text="Fechar", command=dlg.destroy)
        btn_close.pack(pady=5, padx=5, side=tk.RIGHT)

        def fetch_thread():
            """Busca a lista de problemas em um thread."""
            try:
                problems = self.zabbix_client.get_host_problems_list(host_id)
                self.after(0, update_text, problems)
            except Exception as e:
                self.after(0, update_text, [f"Erro ao buscar: {e}"])
                
        def update_text(problems_list):
            """Atualiza a caixa de texto com os resultados."""
            txt.config(state="normal")
            txt.delete("1.0", tk.END)
            if problems_list:
                txt.insert(tk.END, "\n".join(problems_list))
            else:
                txt.insert(tk.END, "Nenhum problema encontrado.")
            txt.config(state="disabled")

        # Inicia a busca
        threading.Thread(target=fetch_thread, daemon=True).start()
    # --- FIM DA NOVA FUNÇÃO ---


    def determine_command_profile(self, os, hardware, hostname):
        # (Função sem mudança)
        if 'fortiswitch' in os: return 'fortiswitch'
        if 'fortios' in os: return 'fortinet_firewall'
        if 'cisco' in os and ('router' in hardware or 'isr' in hardware): return 'cisco_router'
        if 'cisco' in os and 'switch' in hardware: return 'cisco_switch'
        if 'huawei' in os: return 'huawei_switch'
        if 'rt' in hostname: return 'cisco_router'
        if 'fw' in hostname: return 'fortinet_firewall'
        if 'fsw' in hostname or ('forti' in hostname and 'sw' in hostname): return 'fortiswitch'
        if 'sw' in hostname: return 'cisco_switch'
        print(f"DEBUG: Nenhum perfil encontrado para OS='{os}', HW='{hardware}', Hostname='{hostname}'")
        return 'default'

    def populate_commands_frame(self, profile_key):
        # (Função sem mudança)
        for widget in self.cmd_frame.winfo_children():
            widget.destroy()
        self.command_vars.clear()
        btn_frame = ttk.Frame(self.cmd_frame); btn_frame.pack(fill=tk.X, padx=5, pady=2)
        btn_select_all = ttk.Button(btn_frame, text="Selecionar Todos", command=self.select_all_commands)
        btn_select_all.pack(side=tk.LEFT, padx=(0, 5))
        btn_deselect_all = ttk.Button(btn_frame, text="Desmarcar Todos", command=self.deselect_all_commands)
        btn_deselect_all.pack(side=tk.LEFT)
        ttk.Separator(self.cmd_frame, orient='horizontal').pack(fill='x', pady=5, padx=5)
        scroll_canvas = tk.Canvas(self.cmd_frame, borderwidth=0); scroll_frame = ttk.Frame(scroll_canvas)
        scrollbar = ttk.Scrollbar(self.cmd_frame, orient="vertical", command=scroll_canvas.yview)
        scroll_canvas.configure(yscrollcommand=scrollbar.set); scrollbar.pack(side="right", fill="y")
        scroll_canvas.pack(side="left", fill="both", expand=True)
        scroll_canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        def on_frame_configure(event): scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all"))
        scroll_frame.bind("<Configure>", on_frame_configure)
        commands_list = COMMAND_PROFILES.get(profile_key, [])
        if not commands_list:
            btn_select_all.config(state="disabled"); btn_deselect_all.config(state="disabled")
            ttk.Label(scroll_frame, text="Nenhum comando 'Show' definido para este host.").pack(padx=5, pady=5)
            return
        btn_select_all.config(state="normal"); btn_deselect_all.config(state="normal")
        for desc, cmd in commands_list:
            var = tk.BooleanVar()
            cb = ttk.Checkbutton(scroll_frame, text=desc, variable=var)
            cb.pack(anchor=tk.W, padx=5, pady=2, fill='x')
            self.command_vars.append((var, desc, cmd))
            
    def update_action_buttons(self, profile_key):
        # (Função sem mudança)
        for widget in self.action_button_frame.winfo_children():
            widget.destroy()
        if profile_key == 'default': return
        if profile_key in ('fortinet_firewall', 'fortiswitch'):
            btn_connect = ttk.Button(self.action_button_frame, text="Conectar (PuTTY)", command=self.open_putty_connection)
            btn_connect.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
            btn_web = ttk.Button(self.action_button_frame, text="Acessar na Web", command=self.open_web_access)
            btn_web.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))
        else:
            btn_connect = ttk.Button(self.action_button_frame, text="Conectar (PuTTY)", command=self.open_putty_connection)
            btn_connect.pack(fill=tk.X)

    def open_putty_connection(self):
        # (Função sem mudança)
        if not self.settings:
            messagebox.showerror("Erro", "Credenciais SSH não configuradas.")
            return
        selected_indices = self.lb_hosts.curselection()
        if not selected_indices:
            messagebox.showwarning("Seleção inválida", "Por favor, selecione um Host.")
            return
        selected_string = self.lb_hosts.get(selected_indices[0])
        host_data = self.hosts_data_map.get(selected_string)
        if not host_data:
            messagebox.showwarning("Seleção inválida", "Por favor, selecione um Host.")
            return
        host_ip = host_data['actual_ip']
        ssh_user = self.settings['ssh_user']
        ssh_pass = self.settings['ssh_pass']
        putty_path = 'putty.exe' 
        login_string = f"{ssh_user}@{host_ip}"
        command_args = [putty_path, '-ssh', login_string, '-pw', ssh_pass]
        safe_command_args = [putty_path, '-ssh', login_string, '-pw', '********']
        try:
            print(f"Iniciando PuTTY com: {safe_command_args}")
            subprocess.Popen(command_args) 
        except FileNotFoundError:
            messagebox.showerror("Erro: PuTTY não encontrado", "'putty.exe' não encontrado.", parent=self)
        except Exception as e:
            messagebox.showerror("Erro ao abrir PuTTY", f"Ocorreu um erro: {e}", parent=self)

    def open_web_access(self):
        # (Função sem mudança)
        selected_indices = self.lb_hosts.curselection()
        if not selected_indices:
            messagebox.showwarning("Seleção inválida", "Por favor, selecione um Host.", parent=self)
            return
        selected_string = self.lb_hosts.get(selected_indices[0])
        host_data = self.hosts_data_map.get(selected_string)
        if not host_data:
            messagebox.showwarning("Seleção inválida", "Por favor, selecione um Host.", parent=self)
            return
        host_ip = host_data['actual_ip'] 
        url = f"https://{host_ip}" 
        try:
            print(f"Abrindo {url} no navegador...")
            webbrowser.open_new(url)
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível abrir o navegador.\n{e}", parent=self)
            
    
    # --- Diálogo Avançado (sem mudança) ---
    def open_advanced_commands_dialog(self, default_profile_commands=None, host_ip_display=None, profile_key='default', hosts_list=None):
        # (Toda esta seção, incluindo a lógica do botão 'Run', permanece a mesma da última vez)
        if hosts_list is None: hosts_list = []
        num_hosts = len(hosts_list)
        
        dlg = tk.Toplevel(self)
        dlg.title(f"Comandos Avançados ({profile_key}) - {host_ip_display}")
        dlg.geometry("750x700") 
        dlg.transient(self)
        dlg.grab_set()

        frm = ttk.Frame(dlg, padding=8)
        frm.pack(fill=tk.BOTH, expand=True)

        if num_hosts > 1: label_text = f"Aplicando em {num_hosts} hosts selecionados"
        else: label_text = f"Aplicando em: {host_ip_display}"
        ttk.Label(frm, text=label_text, font=("-weight bold", 10)).pack(anchor=tk.W)
        ttk.Separator(frm, orient='horizontal').pack(fill='x', pady=5)

        panes = ttk.PanedWindow(frm, orient=tk.VERTICAL)
        panes.pack(fill=tk.BOTH, expand=True)
        show_config_frame = ttk.Frame(panes); panes.add(show_config_frame, weight=3)
        ttk.Label(show_config_frame, text="Show commands (uma por linha):").pack(anchor=tk.W)
        show_txt = tk.Text(show_config_frame, height=8); show_txt.pack(fill=tk.X, pady=4, expand=True)
        ttk.Label(show_config_frame, text="Config commands (uma por linha):").pack(anchor=tk.W)
        snippet_frame = ttk.Frame(show_config_frame); snippet_frame.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(snippet_frame, text="Snippets:").pack(side=tk.LEFT)
        snippets_for_profile = VENDOR_CONFIG_SNIPPETS.get(profile_key, {})
        snippet_names = ["--- Selecione um Snippet ---"] + list(snippets_for_profile.keys())
        snippet_combo = ttk.Combobox(snippet_frame, values=snippet_names, state="readonly", width=40)
        snippet_combo.pack(side=tk.LEFT, padx=6); snippet_combo.set("--- Selecione um Snippet ---")
        config_txt = tk.Text(show_config_frame, height=12); config_txt.pack(fill=tk.X, pady=4, expand=True)
        
        def on_snippet_select(event):
            snippet_name = snippet_combo.get()
            command_text = snippets_for_profile.get(snippet_name, '')
            if command_text: config_txt.insert(tk.END, command_text + "\n")
            snippet_combo.set("--- Selecione um Snippet ---") 
        snippet_combo.bind("<<ComboboxSelected>>", on_snippet_select)
        
        iface_tools_frame = ttk.Frame(panes); panes.add(iface_tools_frame, weight=2)
        iface_entry_frame = ttk.Frame(iface_tools_frame); iface_entry_frame.pack(fill=tk.X)
        ttk.Label(iface_entry_frame, text="Interfaces (ex: Gi0/1-3,port10):").pack(side=tk.LEFT)
        iface_entry = ttk.Entry(iface_entry_frame); iface_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        
        if num_hosts == 1:
            btn_fetch = ttk.Button(iface_entry_frame, text="Buscar Interfaces")
            btn_fetch.pack(side=tk.LEFT)
            iface_list_frame = ttk.Labelframe(iface_tools_frame, text="Interfaces Encontradas (clique para adicionar)")
            iface_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            iface_list_sb = ttk.Scrollbar(iface_list_frame, orient=tk.VERTICAL)
            iface_listbox = tk.Listbox(iface_list_frame, height=5, yscrollcommand=iface_list_sb.set)
            iface_list_sb.config(command=iface_listbox.yview)
            iface_list_sb.pack(side=tk.RIGHT, fill=tk.Y)
            iface_listbox.pack(fill=tk.BOTH, expand=True)

            def on_interface_select(event):
                try:
                    selected_indices = iface_listbox.curselection()
                    if not selected_indices: return
                    iface_name = iface_listbox.get(selected_indices[0])
                    if "ERRO:" in iface_name or "Buscando..." in iface_name: return
                    current_text = iface_entry.get().strip()
                    if current_text and current_text[-1] == ',': new_text = current_text + iface_name
                    elif current_text: new_text = current_text + "," + iface_name
                    else: new_text = iface_name
                    iface_entry.delete(0, tk.END); iface_entry.insert(0, new_text)
                    iface_listbox.selection_clear(0, tk.END)
                except Exception as e: print(f"Erro ao selecionar interface: {e}")
            iface_listbox.bind('<<ListboxSelect>>', on_interface_select)

            def on_fetch_interfaces():
                iface_listbox.delete(0, tk.END); iface_listbox.insert(0, "Buscando... Por favor, aguarde.")
                btn_fetch.config(state="disabled")
                host_to_fetch = hosts_list[0]
                def fetch_thread():
                    from api_clients import fetch_interfaces_from_host
                    try:
                        interfaces = fetch_interfaces_from_host(
                            host_to_fetch['actual_ip'], self.settings['ssh_user'],
                            self.settings['ssh_pass'], profile_key)
                        dlg.after(0, populate_list, interfaces)
                    except Exception as e: dlg.after(0, populate_list, [f"ERRO: {e}"])
                def populate_list(interfaces):
                    iface_listbox.delete(0, tk.END)
                    if not interfaces: iface_listbox.insert(0, "Nenhuma interface encontrada ou perfil não suportado.")
                    else:
                        for iface in interfaces: iface_listbox.insert(tk.END, iface)
                    btn_fetch.config(state="normal")
                threading.Thread(target=fetch_thread, daemon=True).start()
            btn_fetch.config(command=on_fetch_interfaces)
        
        bottom_frame = ttk.Frame(frm); bottom_frame.pack(fill=tk.X, pady=10)
        opts_frame = ttk.Frame(bottom_frame); opts_frame.pack(fill=tk.X)
        vendor_var = tk.StringVar(value=profile_key) 
        ttk.Label(opts_frame, text="Vendor:").pack(side=tk.LEFT)
        ttk.Entry(opts_frame, textvariable=vendor_var, width=15).pack(side=tk.LEFT, padx=6)
        do_wr_var = tk.BooleanVar(value=False); ttk.Checkbutton(opts_frame, text="Salvar (WR)", variable=do_wr_var).pack(side=tk.LEFT, padx=6)
        save_backup_var = tk.BooleanVar(value=True); ttk.Checkbutton(opts_frame, text="Salvar backup", variable=save_backup_var).pack(side=tk.LEFT, padx=6)
        loop_frame = ttk.Frame(bottom_frame); loop_frame.pack(fill=tk.X, pady=5)
        loop_var = tk.BooleanVar(value=False); ttk.Checkbutton(loop_frame, text="Executar 'Show' em Loop", variable=loop_var).pack(side=tk.LEFT, padx=6)
        ttk.Label(loop_frame, text="Intervalo (s):").pack(side=tk.LEFT)
        loop_interval_var = tk.StringVar(value="5"); ttk.Entry(loop_frame, textvariable=loop_interval_var, width=4).pack(side=tk.LEFT, padx=6)
        if default_profile_commands:
            try:
                show_cmds_list = [c[1] for c in default_profile_commands]
                show_txt.insert("1.0", "\n".join(show_cmds_list))
            except Exception as e: print(f"Erro ao preencher comandos show: {e}")
        btn_fr = ttk.Frame(frm); btn_fr.pack(fill=tk.X, pady=6, side=tk.BOTTOM)
        ttk.Button(btn_fr, text="Run", command=lambda: on_run()).pack(side=tk.RIGHT, padx=6)
        ttk.Button(btn_fr, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT)

        def on_run():
            show_lines = [l.strip() for l in show_txt.get("1.0","end").splitlines() if l.strip()]
            config_lines = [l.strip() for l in config_txt.get("1.0","end").splitlines() if l.strip()]
            interfaces_raw = iface_entry.get().strip()
            vendor = vendor_var.get().strip() or None
            do_wr = do_wr_var.get(); save_backup = save_backup_var.get(); do_loop = loop_var.get()
            try:
                loop_interval = int(loop_interval_var.get());
                if loop_interval < 1: loop_interval = 1
            except: loop_interval = 5
            if do_loop and config_lines:
                messagebox.showwarning("Loop Ativo", "Comandos de 'Config' não serão executados no modo Loop.", parent=dlg)
                config_lines = []; do_wr = False 
            if do_loop and num_hosts > 1:
                messagebox.showerror("Loop Inválido", "O modo Loop só pode ser executado em um host de cada vez.", parent=dlg)
                return
            from api_clients import expand_interface_list
            expanded = expand_interface_list(interfaces_raw)
            final_config = []
            if expanded:
                for cmd in config_lines:
                    if "{INTERFACE}" in cmd or "{INTERFACES}" in cmd:
                        for i in expanded: final_config.append(cmd.replace("{INTERFACE}", i).replace("{INTERFACES}", i))
                    else: final_config.append(cmd)
            else: final_config = config_lines
            payload = {
                'show': show_lines, 'config': final_config, 'vendor': vendor,
                'do_write': do_wr, 'save_backup': save_backup,
                'do_loop': do_loop, 'loop_interval': loop_interval }
            for host_data in hosts_list:
                host_ip_to_use = host_data['actual_ip']
                payload['vendor'] = vendor_var.get().strip() or host_data.get('profile_key', 'cisco_ios')
                SSHOutputWindow(
                    parent=self, host_ip=host_ip_to_use, 
                    ssh_user=self.settings['ssh_user'], ssh_pass=self.settings['ssh_pass'],
                    commands=payload )
            dlg.destroy()
    # --- Fim do Diálogo Avançado ---


    def run_simple_ssh(self):
        # (Função sem mudança)
        if not self.settings:
            messagebox.showerror("Erro", "Credenciais SSH não configuradas.")
            return
        selected_indices = self.lb_hosts.curselection()
        if not selected_indices:
            messagebox.showwarning("Seleção inválida", "Selecione pelo menos um host.")
            return
        commands_to_run = []; vars_to_deselect = [] 
        for var, desc, cmd in self.command_vars:
            if var.get():
                commands_to_run.append((desc, cmd)); vars_to_deselect.append(var) 
        if not commands_to_run:
            messagebox.showwarning("Sem Comandos", "Selecione pelo menos um comando (checkbox).")
            return
        for idx in selected_indices:
            selected_string = self.lb_hosts.get(idx)
            host_data = self.hosts_data_map.get(selected_string)
            if not host_data: continue
            host_ip = host_data['actual_ip']
            SSHOutputWindow(
                parent=self, host_ip=host_ip,
                ssh_user=self.settings['ssh_user'], ssh_pass=self.settings['ssh_pass'],
                commands=commands_to_run )
        for var in vars_to_deselect: var.set(False)


    def open_advanced_ssh_dialog(self):
        # (Função sem mudança)
        if not self.settings:
            messagebox.showerror("Erro", "Credenciais SSH não configuradas.")
            return
        selected_indices = self.lb_hosts.curselection()
        if not selected_indices:
            messagebox.showwarning("Seleção inválida", "Selecione pelo menos um host.")
            return
        hosts_to_configure = []
        for idx in selected_indices:
            host_string = self.lb_hosts.get(idx)
            host_data = self.hosts_data_map.get(host_string)
            if host_data: hosts_to_configure.append(host_data)
        if not hosts_to_configure:
            messagebox.showerror("Erro", "Não foi possível encontrar dados para os hosts selecionados.")
            return
        first_host_data = hosts_to_configure[0]
        host_ip_display = first_host_data['actual_ip']
        num_hosts = len(hosts_to_configure)
        if num_hosts > 1: host_ip_display += f" (+ {num_hosts-1} outros)"
        inventory = first_host_data.get('inventory', {}); os_field = inventory.get('os', '').lower()
        hardware_field = inventory.get('hardware', '').lower(); hostname = first_host_data.get('name', '').lower()
        profile_key = self.determine_command_profile(os_field, hardware_field, hostname)
        for host in hosts_to_configure: host['profile_key'] = profile_key 
        commands_to_prefill = []
        for var, desc, cmd in self.command_vars:
            if var.get(): commands_to_prefill.append((desc, cmd)) 
        if not commands_to_prefill: commands_to_prefill = None
        self.open_advanced_commands_dialog(
            default_profile_commands=commands_to_prefill, host_ip_display=host_ip_display, 
            profile_key=profile_key, hosts_list=hosts_to_configure )


if __name__ == "__main__":
    app = MainApplication()
    app.mainloop()