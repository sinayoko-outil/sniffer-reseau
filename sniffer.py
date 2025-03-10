import sys
import time
import logging
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, get_if_list
except ImportError:
    print("Erreur : Le module 'scapy' n'est pas installé. Installez-le avec 'pip install scapy'.")
    sys.exit(1)

# Configuration du logging
logging.basicConfig(
    filename="traffic_log.txt",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sniffer Réseau GUI")
        self.root.geometry("900x600")
        self.root.configure(bg="#2E2E2E")

        # Récupération des interfaces réseau disponibles
        self.interfaces = get_if_list()
        if not self.interfaces:
            self.interfaces = ["Aucune interface détectée"]

        # Utilisation d'une variable d'interface avec une valeur par défaut
        self.interface_var = tk.StringVar(value=self.interfaces[0])
        
        # Attributs pour le contrôle du sniffing et les statistiques
        self.sniffing_active = False
        self.stats = {"packet_count": 0}

        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Interface réseau :").grid(row=0, column=0, padx=5, pady=5)
        # Combobox pour la sélection d'interface
        self.interface_combobox = ttk.Combobox(frame, textvariable=self.interface_var, values=self.interfaces, state="readonly", width=20)
        self.interface_combobox.grid(row=0, column=1, padx=5, pady=5)
        self.interface_combobox.current(0)
        
        self.start_button = ttk.Button(frame, text="Démarrer", command=self.start_sniffing)
        self.start_button.grid(row=0, column=2, padx=5, pady=5)
        
        self.stop_button = ttk.Button(frame, text="Arrêter", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)
        
        self.text_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20, width=90, bg="#1E1E1E", fg="white")
        self.text_area.grid(row=1, column=0, columnspan=4, pady=10)
        
        self.stats_label = ttk.Label(frame, text="Paquets capturés : 0", foreground="white", background="#2E2E2E")
        self.stats_label.grid(row=2, column=0, columnspan=4, pady=5)
    
    def log_packet(self, packet):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] "

        if IP in packet:
            log_entry += f"{packet[IP].src} -> {packet[IP].dst} "
        if TCP in packet:
            log_entry += f"TCP Port: {packet[TCP].dport} "
        if UDP in packet:
            log_entry += f"UDP Port: {packet[UDP].dport} "
        if DNS in packet and packet[DNS].qr == 0:
            try:
                domain = packet[DNS].qd.qname.decode()
            except AttributeError:
                domain = str(packet[DNS].qd.qname)
            log_entry += f"DNS Request: {domain}"
        
        logging.info(log_entry)
        self.text_area.insert(tk.END, log_entry + "\n")
        self.text_area.yview(tk.END)
        
        self.stats["packet_count"] += 1
        self.stats_label.config(text=f"Paquets capturés : {self.stats['packet_count']}")

    def packet_callback(self, packet):
        if self.sniffing_active:
            self.log_packet(packet)
    
    def sniff_packets(self, interface):
        # Boucle de sniffing avec timeout pour permettre l'arrêt propre
        while self.sniffing_active:
            sniff(iface=interface, prn=self.packet_callback, store=0, timeout=1)
    
    def start_sniffing(self):
        if not self.sniffing_active:
            self.sniffing_active = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, "\nSniffing en cours...\n")
            interface = self.interface_var.get()
            # Lancement du sniffing dans un thread dédié (daemon pour quitter proprement)
            self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(interface,), daemon=True)
            self.sniff_thread.start()
    
    def stop_sniffing(self):
        if self.sniffing_active:
            self.sniffing_active = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.text_area.insert(tk.END, "\nSniffing arrêté.\n")
            # Le thread se terminera dès que la boucle while se termine

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()
