import tkinter as tk
from tkinter import ttk, scrolledtext
import queue, threading
# NOVO: Imports para o loop
import time, datetime 
from api_clients import SSHClient, execute_commands, restore_backup


class SSHOutputWindow(tk.Toplevel):
    def __init__(self, parent, host_ip, ssh_user, ssh_pass, commands):
        super().__init__(parent)
        self.title(f"Saída SSH - {host_ip}")
        self.geometry("900x500")

        self.host = host_ip
        self.user = ssh_user
        self.password = ssh_pass
        self.commands = commands # Pode ser dict (avançado) ou list (simples)

        self.log_queue = queue.Queue()
        self.last_backup = None
        
        self.running = True # Flag para controlar o loop

        # ---------- UI ----------
        frame = ttk.Frame(self, padding=5)
        frame.pack(fill=tk.BOTH, expand=True)

        self.text_widget = scrolledtext.ScrolledText(frame, state="normal", bg="black", fg="white", font=("Consolas", 10))
        self.text_widget.pack(fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=4)

        # Rollback (inicialmente desabilitado)
        self.rollback_btn = ttk.Button(
            btn_frame, text="Rollback (aplicar backup)",
            command=self.do_rollback, state="disabled"
        )
        self.rollback_btn.pack(side=tk.RIGHT, padx=6)

        ttk.Button(btn_frame, text="Fechar", command=self.on_close).pack(side=tk.RIGHT, padx=6)
        
        # Seta o protocolo de fechar janela
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Thread para execução SSH
        t = threading.Thread(target=self.worker_thread, daemon=True)
        t.start()

        self.check_ssh_queue()

    # -----------------------------------------------------
    # UTIL (MODIFICADO para aceitar clear_screen)
    # -----------------------------------------------------
    def log_message(self, message, clear_screen=False):
        """Adiciona mensagem ao log, limpando a tela se 'clear_screen' for True."""
        if not self.text_widget.winfo_exists():
            return
            
        self.text_widget.configure(state="normal")
        
        if clear_screen:
            self.text_widget.delete("1.0", tk.END)
            
        self.text_widget.insert(tk.END, message + "\n")
        self.text_widget.see(tk.END) # Auto-scroll para o fim
        self.text_widget.configure(state="disabled")

    # -----------------------------------------------------
    # WORKER THREAD PRINCIPAL (MODIFICADO para Loop)
    # -----------------------------------------------------
    def worker_thread(self):
        try:
            self.log_queue.put(f"--- Conectando em {self.host} ---")

            # ---------------------------------------------
            # Caso: Automação avançada (Netmiko, DICT)
            # ---------------------------------------------
            if isinstance(self.commands, dict):
                payload = self.commands
                vendor = payload.get("vendor")
                show_cmds = payload.get("show", [])
                config_cmds = payload.get("config", [])
                do_write = payload.get("do_write", False)
                save_backup = payload.get("save_backup", True)
                
                # --- Lógica de Loop ---
                do_loop = payload.get("do_loop", False)
                loop_interval = payload.get("loop_interval", 5)
                # ---------------------------

                conn = None # Definir fora para o finally
                try:
                    # Conecta (usando a função de api_clients)
                    from api_clients import open_connection_netmiko
                    conn = open_connection_netmiko(self.host, self.user, self.password, vendor=vendor)
                    self.log_queue.put("--- Conexão Netmiko estabelecida ---")

                    # 1. Backup (EXECUTADO UMA VEZ)
                    if save_backup:
                        self.log_queue.put("--- Iniciando backup da configuração ---")
                        try:
                            # (Lógica de backup de api_clients.execute_commands)
                            if 'cisco' in conn.device_type:
                                backup_out = conn.send_command("show running-config")
                            elif 'forti' in conn.device_type:
                                backup_out = conn.send_command("show full-configuration")
                            elif 'huawei' in conn.device_type:
                                backup_out = conn.send_command("display current-configuration")
                            else:
                                backup_out = conn.send_command("show running-config")
                            
                            from api_clients import save_config_backup
                            self.last_backup = save_config_backup(backup_out, self.host)
                            self.log_queue.put(f"--- Backup salvo: {self.last_backup} ---")
                            # Habilita o botão de rollback na thread principal da UI
                            self.after(0, self.rollback_btn.config, {"state": "normal"})
                        except Exception as e:
                            self.log_queue.put(f"*** ERRO NO BACKUP: {e} ***")

                    # 2. Config (EXECUTADO UMA VEZ, se não houver loop)
                    if config_cmds and not do_loop:
                        self.log_queue.put(f"--- Aplicando {len(config_cmds)} linhas de configuração ---")
                        try:
                            out = conn.send_config_set(config_cmds, exit_config_mode=True)
                            self.log_queue.put(f">>> SAÍDA CONFIG:\n{out}")
                            
                            if do_write:
                                self.log_queue.put("--- Salvando configuração (WR) ---")
                                if 'cisco' in conn.device_type:
                                    save_out = conn.send_command("write memory")
                                elif 'forti' in conn.device_type:
                                    save_out = conn.send_command("execute config-save")
                                elif 'huawei' in conn.device_type:
                                    save_out = conn.send_command("save", expect_string=r'\[Y/N\]')
                                    save_out += conn.send_command("Y", expect_string=r'>')
                                else:
                                    save_out = conn.send_command("write memory")
                                self.log_queue.put(f"SAÍDA SAVE:\n{save_out}")
                                
                        except Exception as e:
                             self.log_queue.put(f"*** ERRO NA CONFIG: {e} ***")
                    
                    # 3. Show (EXECUTADO EM LOOP ou UMA VEZ)
                    if not show_cmds:
                        self.log_queue.put("--- Nenhum comando 'Show' para executar ---")
                    
                    elif do_loop:
                        # --- NOVO: MODO LOOP COM CLEAR ---
                        self.log_queue.put(f"--- INICIANDO MODO LOOP (Intervalo: {loop_interval}s) ---")
                        self.log_queue.put("--- Pressione 'Fechar' na janela para parar ---")
                        
                        while self.running:
                            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            # Constroi um bloco de saída único
                            output_block = f"--- ATUALIZANDO ({ts}) ---\n"
                            
                            for cmd in show_cmds:
                                output_block += f"\n>>> CMD: {cmd}\n"
                                try:
                                    out = conn.send_command(cmd)
                                    output_block += out
                                except Exception as e:
                                    output_block += f"*** ERRO: {e} ***"
                            
                            # Envia o bloco inteiro como uma tupla especial para a fila
                            self.log_queue.put(("loop_update", output_block))
                            
                            # Verifica se deve parar ANTES de dormir
                            if not self.running:
                                break
                            time.sleep(loop_interval)
                        
                        self.log_queue.put("--- MODO LOOP INTERROMPIDO PELO USUÁRIO ---")
                        # ---------------------------------
                        
                    else:
                        # --- MODO: Execução Única ---
                        self.log_queue.put("--- Executando comandos 'Show' (Execução única) ---")
                        for cmd in show_cmds:
                            self.log_queue.put(f"\n>>> CMD: {cmd}")
                            out = conn.send_command(cmd)
                            self.log_queue.put(out)

                except Exception as e:
                    self.log_queue.put(f"*** ERRO DE CONEXÃO/EXECUÇÃO NETMIKO: {e} ***")
                finally:
                    if conn:
                        conn.disconnect()
                        self.log_queue.put("--- Conexão Netmiko fechada ---")
                
                return # Finaliza a parte do Netmiko

            # ---------------------------------------------
            # Fallback: Execução simples (Paramiko, LIST)
            # ---------------------------------------------
            client = SSHClient(self.host, self.user, self.password) # Usa o cliente de api_clients
            try:
                client.client.connect(
                    client.host, username=client.user, password=client.password,
                    timeout=10, look_for_keys=False, allow_agent=False
                )
                self.log_queue.put("--- Conexão SSH (Paramiko) estabelecida ---")

                # 'self.commands' é uma LISTA de tuplas (desc, cmd)
                for desc, cmd in self.commands:
                    # Verifica se o usuário fechou a janela no meio
                    if not self.running:
                        self.log_queue.put("--- Execução interrompida pelo usuário ---")
                        break
                        
                    self.log_queue.put(f"\n--- CMD: {desc} ({cmd}) ---")
                    try:
                        stdin, stdout, stderr = client.client.exec_command(cmd)
                        out = stdout.read().decode('utf-8')
                        err = stderr.read().decode('utf-8')
                        self.log_queue.put(out)
                        if err:
                            self.log_queue.put(f"*** ERRO (stderr): {err} ***")
                    except Exception as e:
                        self.log_queue.put(f"*** ERRO executando {cmd}: {e} ***")

            except Exception as e:
                self.log_queue.put(f"*** FALHA SSH (Paramiko): {e} ***")

            finally:
                try:
                    client.client.close()
                    self.log_queue.put("--- Conexão SSH (Paramiko) fechada ---")
                except:
                    pass
                
        except Exception as e:
            self.log_queue.put(f"*** FALHA GERAL NO WORKER: {e} ***")
        finally:
            # Sinaliza para a GUI que o thread terminou (MUITO IMPORTANTE)
            self.log_queue.put(None)

    # -----------------------------------------------------
    # ROLLBACK
    # -----------------------------------------------------
    def do_rollback(self):
        if not self.last_backup:
            self.log_queue.put("Nenhum backup disponível para rollback.")
            return

        self.log_queue.put(f"--- Iniciando rollback aplicando {self.last_backup} ---")
        self.rollback_btn.config(state="disabled") # Desabilita para evitar clique duplo

        # Roda o rollback em um novo thread para não travar a UI
        def rollback_thread():
            try:
                res = restore_backup(self.host, self.user, self.password, self.last_backup)

                if res.get("errors"):
                    self.log_queue.put("*** Erros no rollback: ***\n" + "\n".join(res["errors"]))
                else:
                    self.log_queue.put(f"--- Rollback aplicado com sucesso (Linhas: {res.get('applied_lines')}) ---")

            except Exception as e:
                self.log_queue.put(f"*** FALHA CRÍTICA NO ROLLBACK: {e} ***")
            finally:
                # Re-habilita o botão (ou não, talvez seja melhor deixar desabilitado)
                # self.after(0, self.rollback_btn.config, {"state": "normal"})
                pass
        
        threading.Thread(target=rollback_thread, daemon=True).start()


    # -----------------------------------------------------
    # PROCESSAMENTO DA QUEUE (MODIFICADO para Loop)
    # -----------------------------------------------------
    def check_ssh_queue(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                
                if line is None:
                    self.log_message("--- Execução SSH concluída ---", clear_screen=False)
                    return
                
                # --- NOVO: Verifica se é um update de loop ---
                elif isinstance(line, tuple) and line[0] == "loop_update":
                    # line[1] é o bloco de texto
                    self.log_message(line[1], clear_screen=True)
                # -------------------------------------------
                
                else:
                    # É uma string normal (log de conexão, erro, etc.)
                    self.log_message(str(line), clear_screen=False)

        except queue.Empty:
            pass

        # Agenda a próxima verificação apenas se a janela ainda existir
        if self.running:
            self.after(100, self.check_ssh_queue)

    # -----------------------------------------------------
    # FECHAR JANELA (MODIFICADO)
    # -----------------------------------------------------
    def on_close(self):
        if self.running:
            print("Fechando janela de output. Sinalizando para o thread parar.")
            # Define a flag para False. O thread vai ver isso e parar o loop.
            self.running = False 
        
        # Destrói a janela de fato
        try:
            self.destroy()
        except tk.TclError:
            pass