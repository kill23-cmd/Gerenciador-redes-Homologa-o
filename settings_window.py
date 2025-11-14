# settings_window.py
import tkinter as tk
from tkinter import ttk, messagebox
import config_manager

class SettingsWindow(tk.Toplevel):
    
    # ***** MUDANÇA AQUI *****
    # Adicionado 'settings_data' para receber as configurações da janela principal
    def __init__(self, parent, settings_data, save_callback):
    # ************************
        super().__init__(parent)
        self.title("Opções de Configuração")
        self.geometry("600x450") 
        self.transient(parent)
        self.grab_set()

        self.save_callback = save_callback
        
        # ***** MUDANÇA AQUI *****
        # Não lê mais o arquivo, usa os dados recebidos.
        # Se 'settings_data' for None (primeira execução), usa um dicionário vazio {}.
        self.settings = settings_data or {}
        # ************************

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        # --- Zabbix Frame ---
        zabbix_frame = ttk.Labelframe(main_frame, text="Credenciais Zabbix API", padding="10")
        zabbix_frame.pack(fill=tk.X, pady=5)
        
        zabbix_frame.columnconfigure(0, weight=1) 

        ttk.Label(zabbix_frame, text="URL (ex: http://zabbix.com/api_jsonrpc.php):").grid(row=0, column=0, sticky=tk.W)
        self.zabbix_url = ttk.Entry(zabbix_frame, width=40)
        self.zabbix_url.grid(row=1, column=0, sticky=tk.W+tk.E, pady=(0, 5))
        # Agora esta linha preenche o campo se self.settings tiver dados
        self.zabbix_url.insert(0, self.settings.get('zabbix_url', ''))

        ttk.Label(zabbix_frame, text="Usuário:").grid(row=2, column=0, sticky=tk.W)
        self.zabbix_user = ttk.Entry(zabbix_frame)
        self.zabbix_user.grid(row=3, column=0, sticky=tk.W+tk.E, pady=(0, 5))
        self.zabbix_user.insert(0, self.settings.get('zabbix_user', ''))

        ttk.Label(zabbix_frame, text="Senha:").grid(row=4, column=0, sticky=tk.W)
        self.zabbix_pass = ttk.Entry(zabbix_frame, show="*")
        self.zabbix_pass.grid(row=5, column=0, sticky=tk.W+tk.E, pady=(0, 5))
        self.zabbix_pass.insert(0, self.settings.get('zabbix_pass', ''))

        # --- SSH Frame ---
        ssh_frame = ttk.Labelframe(main_frame, text="Credenciais SSH Host", padding="10")
        ssh_frame.pack(fill=tk.X, pady=5)
        
        ssh_frame.columnconfigure(0, weight=1)

        ttk.Label(ssh_frame, text="Usuário SSH:").grid(row=0, column=0, sticky=tk.W)
        self.ssh_user = ttk.Entry(ssh_frame)
        self.ssh_user.grid(row=1, column=0, sticky=tk.W+tk.E, pady=(0, 5))
        self.ssh_user.insert(0, self.settings.get('ssh_user', ''))

        ttk.Label(ssh_frame, text="Senha SSH:").grid(row=2, column=0, sticky=tk.W)
        self.ssh_pass = ttk.Entry(ssh_frame, show="*")
        self.ssh_pass.grid(row=3, column=0, sticky=tk.W+tk.E, pady=(0, 5))
        self.ssh_pass.insert(0, self.settings.get('ssh_pass', ''))

        # --- Botões ---
        button_frame = ttk.Frame(ssh_frame) 
        button_frame.grid(row=4, column=0, sticky=tk.E, pady=(10, 0)) 

        save_button = ttk.Button(button_frame, text="Salvar", command=self.save)
        save_button.pack(side=tk.RIGHT, padx=5)
        
        cancel_button = ttk.Button(button_frame, text="Cancelar", command=self.destroy)
        cancel_button.pack(side=tk.RIGHT)

    def save(self):
        # A lógica de salvar não muda
        data = {
            'zabbix_url': self.zabbix_url.get(),
            'zabbix_user': self.zabbix_user.get(),
            'zabbix_pass': self.zabbix_pass.get(),
            'ssh_user': self.ssh_user.get(),
            'ssh_pass': self.ssh_pass.get()
        }
        
        if not all(data.values()):
            messagebox.showwarning("Campos incompletos", "Por favor, preencha todas as credenciais.", parent=self)
            return

        try:
            config_manager.save_settings(data)
            messagebox.showinfo("Sucesso", "Configurações salvas!", parent=self)
            
            if self.save_callback:
                self.save_callback()
                
            self.destroy()
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível salvar as configurações:\n{e}", parent=self)