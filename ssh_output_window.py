# ssh_output_window.py
import tkinter as tk
from tkinter import ttk, scrolledtext
import queue
from api_clients import SSHClient

class SSHOutputWindow(tk.Toplevel):
    def __init__(self, parent, host_ip, ssh_user, ssh_pass, commands):
        super().__init__(parent)
        self.title(f"Saída SSH - {host_ip}")
        self.geometry("900x500")

        self.log_queue = queue.Queue()
        
        # Frame para o log
        log_frame = ttk.Frame(self, padding="5")
        log_frame.pack(expand=True, fill=tk.BOTH)

        self.log_output = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, 
                                                    bg="black", fg="white", 
                                                    font=("Consolas", 10))
        self.log_output.pack(expand=True, fill=tk.BOTH)
        self.log_output.configure(state='disabled')

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Inicia a conexão e execução
        try:
            ssh = SSHClient(host_ip, ssh_user, ssh_pass)
            ssh.execute_commands_to_queue(commands, self.log_queue)
        except Exception as e:
            self.log_message(f"*** FALHA AO INICIAR SSH: {e} ***")
            self.log_message(None) # Para ativar o loop de verificação

        # Inicia o loop para verificar a fila
        self.check_ssh_queue()

    def log_message(self, message):
        """Adiciona uma mensagem ao widget de log."""
        if self.log_output.winfo_exists():
            self.log_output.configure(state='normal')
            self.log_output.insert(tk.END, message + "\n")
            self.log_output.see(tk.END) # Auto-scroll
            self.log_output.configure(state='disabled')

    def check_ssh_queue(self):
        """Verifica a fila de saída do thread SSH e atualiza o log."""
        try:
            while True:
                line = self.log_queue.get_nowait()
                if line is None: # Sinal de fim do thread
                    self.log_message("--- Execução SSH concluída ---")
                    return # Para o loop
                else:
                    self.log_message(line)
        except queue.Empty:
            pass # Fila vazia, continua esperando
            
        # Agenda a próxima verificação
        self.after(100, self.check_ssh_queue)
    
    def on_close(self):
        # TODO: Adicionar lógica para parar o thread SSH se ainda estiver rodando
        print("Fechando janela de output.")
        self.destroy()