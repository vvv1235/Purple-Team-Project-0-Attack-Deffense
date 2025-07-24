import os
import psutil
import socket
import subprocess
import ctypes
import tkinter as tk
from tkinter import messagebox


# Obtem conexoes remotas e os processos associados.
def get_remote_connections():
    connections = psutil.net_connections(kind='inet')
    remote_connections = []
    for conn in connections:
        try:
            if conn.raddr:  # Se há um endereço remoto
                remote_ip, remote_port = conn.raddr
                local_port = conn.laddr.port
                process = psutil.Process(conn.pid)
                process_name = process.name()
                remote_connections.append({
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process_name": process_name,
                    "pid": conn.pid
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass  # Ignora processos que não estão mais disponíveis
    return remote_connections


# Verifica se o servidor remoto é desconhecido.
def is_unknown_server(remote_ip):
    try:
        socket.gethostbyaddr(remote_ip)
        return False
    except socket.herror:
        return True


# Bloqueia o acesso à internet de um processo usando o Firewall do Windows.
def block_process_in_firewall(pid):
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        rule_name = f"Block_{process_name}_{pid}"

        print(f"Bloqueando o processo '{process_name}' (PID: {pid}) no firewall...")
        
        # Cria uma regra no firewall para bloquear o processo
        subprocess.run(
            f"netsh advfirewall firewall add rule name={rule_name} dir=out program=\"{process.exe()}\" action=block",
            shell=True,
            check=True
        )
        print(f"O processo '{process_name}' foi bloqueado com sucesso.")
    except Exception as e:
        print(f"Erro ao bloquear o processo no firewall: {e}")


# Exibe um popup para decisão do usuário.
def show_popup(suspicious_processes):
    root = tk.Tk()
    root.withdraw()  # Oculta a janela principal

    if suspicious_processes:
        message = "Seu sistema provavelmente foi hackeado. Processos suspeitos encontrados:\n\n"
        for conn in suspicious_processes:
            message += f" - Processo: {conn['process_name']}, PID: {conn['pid']}, IP Remoto: {conn['remote_ip']}\n"

        message += "\nGostaria de bloquear esses processos no firewall?"
        result = messagebox.askyesno("Alerta de Segurança", message)

        if result:
            for conn in suspicious_processes:
                block_process_in_firewall(conn["pid"])
            messagebox.showinfo("Sucesso", "Os processos maliciosos foram bloqueados com sucesso.")
        else:
            messagebox.showwarning("Aviso", "Os processos suspeitos não foram bloqueados. Risco potencial!")
    else:
        messagebox.showinfo("Segurança do Sistema", "Nenhum servidor desconhecido detectado. O sistema parece seguro.")


def main():
    tcpview_path = "C:\\Program Files (x86)\\TCPView\\tcpview.exe"
    if os.path.exists(tcpview_path):
        subprocess.run([tcpview_path], shell=True)
    else:
        print(f"TCPView não foi encontrado no caminho especificado: {tcpview_path}")

    print("Analisando conexoes remotas...")
    remote_connections = get_remote_connections()
    suspicious = [conn for conn in remote_connections if is_unknown_server(conn["remote_ip"])]

    show_popup(suspicious)


# Garantir privilégios administrativos no Windows
if __name__ == "__main__":
    if os.name == "nt":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print("Por favor, execute o script como administrador.")
                exit(1)
        except AttributeError:
            pass
    main()
