from tkinter import *
from scapy.all import *
from datetime import datetime
from tkinter import filedialog, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque
import threading
import time
import matplotlib.pyplot as plt
import sqlite3 
import os
import json
from datetime import datetime
from statistique import *


#variable global
stop_sniff_event = threading.Event()

#Enregistrement dans un fichier

def enregistrer_dans_json(ip_src, payload):
    try:
        payload_str = payload.decode("utf-8", errors="ignore")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = f"{ip_src}.json"

        if os.path.exists(filename):
            with open(filename, "r") as f:
                data = json.load(f)
        else:
            data = {}

        data[timestamp] = payload_str

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"[!] Erreur JSON : {e}")

#Connection Base de donner et operation
conn = sqlite3.connect("Ip_data", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS ip_info (
        ip_addr TEXT NOT NULL UNIQUE,
        nb_conn INTEGER NOT NULL
    )
""")
conn.commit()
conn.close()

def traiter_paquet(pkt):
    if pkt.haslayer("IP") and pkt.haslayer("TCP") and pkt.haslayer("Raw"):
        try:
            payload = pkt.getlayer("Raw").load
            if b"GET" in payload[:10] or b"POST" in payload[:10]:
                ip_src = str(pkt.getlayer("IP").src)

                cursor.execute("""
                    INSERT INTO ip_info (ip_addr, nb_conn)
                    VALUES (?, 1)
                    ON CONFLICT(ip_addr) DO UPDATE SET nb_conn = nb_conn + 1;
                """, (ip_src,))
                conn.commit()

                enregistrer_dans_json(ip_src, payload)
        except Exception as e:
            print(f"[!] Erreur traitement : {e}")


# Section Fonction
def show_realtime_traffic():
    traffic_window = Toplevel(fenetre)
    traffic_window.title("Traffic en temps réel")
    traffic_window.geometry("700x400")
    traffic_window.configure(bg="#f8f8ff")
    
    interval = 1 
    max_points = 60
    traffic_data = deque([0]*max_points, maxlen=max_points)

    fig, ax = plt.subplots(figsize=(7, 3))
    line, = ax.plot(range(max_points), list(traffic_data), color='blue')
    ax.set_title("Nombre de paquets capturés par seconde")
    ax.set_xlabel("Temps (secondes)")
    ax.set_ylabel("Paquets/s")
    plt.tight_layout()

    canvas = FigureCanvasTkAgg(fig, master=traffic_window)
    canvas.get_tk_widget().pack(fill=BOTH, expand=True)

    def update_traffic():
        prev_count = len(ListPaquet)
        while True:
            time.sleep(interval)
            current_count = len(ListPaquet)
            packets_per_sec = current_count - prev_count
            prev_count = current_count

            traffic_data.append(packets_per_sec)

            line.set_ydata(list(traffic_data))
            line.set_xdata(range(len(traffic_data)))
            ax.relim()
            ax.autoscale_view()
            canvas.draw()

            if not traffic_window.winfo_exists():
                break

    threading.Thread(target=update_traffic, daemon=True).start()

# Liste pour stocker les paquets capturés
ListPaquet = []
def on_select(event):
    widget = event.widget
    selection = widget.curselection()
    if selection:
        index = selection[0]
        ChangeIp(index)
        ChangeTcp(index)
        ChangeHttp(index)
        print(ListPaquet[index].show())
        print(f"Index sélectionné : {index}")

# Fonction pour afficher les informations IP
def ChangeIp(ind):
    Attr_Ip = ["src", "dst", "flags", "version", "ttl", "frag", "id", "len", "tos"]
    ip_layer = ListPaquet[ind].getlayer("IP")
    IpInfo.delete(0, END)
    if ip_layer:
        for attr in Attr_Ip:
            value = getattr(ip_layer, attr, "N/A")
            IpInfo.insert(END, f"{attr}: {value}")
        if str(ip_layer.proto) == "6":
            IpInfo.insert(END, "proto: tcp")
        else:
            IpInfo.insert(END, "proto: udp")

# Fonction pour afficher les informations TCP
def ChangeTcp(ind):
    Attr_Tcp = ["sport", "dport", "flags", "seq", "ack", "dataofs", "reserved", "window", "chksum"]
    tcp_layer = ListPaquet[ind].getlayer("TCP")
    TcpInfo.delete(0, END)
    if tcp_layer:
        for attr in Attr_Tcp:
            value = getattr(tcp_layer, attr, "N/A")
            TcpInfo.insert(END, f"{attr}: {value}")
        pkt_time = getattr(ListPaquet[ind], "time", None)
        if pkt_time is not None:
            try:
                TcpInfo.insert(END, str(datetime.fromtimestamp(float(pkt_time))))
            except Exception as e:
                TcpInfo.insert(END, f"Erreur de temps: {e}")
        else:
            TcpInfo.insert(END, "Temps non disponible")

# Fonction pour afficher les informations HTTP
def ChangeHttp(ind):
    if ListPaquet[ind].haslayer("Raw"):
        raw_data_bytes = ListPaquet[ind].getlayer("Raw").load
        try:
            http_layer = raw_data_bytes.decode("utf-8", errors="replace")
        except:
            http_layer = str(raw_data_bytes)

        lignes = http_layer.split("\r\n")
        HttpInfo.delete("1.0", END)

        for ligne in lignes:
            if ligne.strip():
                HttpInfo.insert(END, ligne + "\n")

# Fonction pour traiter les paquets capturés
def traiter(paquet):
    # Vérifier si le paquet a une couche IP et TCP
    if paquet.haslayer("IP") and paquet.haslayer("TCP"):
        ListPaquet.append(paquet)
        traiter_paquet(paquet)  # Traiter le paquet pour l'enregistrement
        summary = paquet.summary()
        # Afficher l'heure de capture et le résumé
        capture_time = time.strftime("%H:%M:%S", time.localtime())
        display_text = f"[{capture_time}] {summary}"
        fenetre.after(0, lambda: ScanList.insert(END, display_text))

# Fonction pour lancer le sniffing 
def lancer_sniff():
    sniff(filter="tcp port 80 or tcp port 8080 or tcp port 9000", prn=traiter, store=False,
          stop_filter=lambda pkt: stop_sniff_event.is_set())

# --- Fonctionnalité : Démarrer la capture de paquets ---
def SniffStart():
    Btn.config(state="disabled")
    Btn2.config(state="normal")
    stop_sniff_event.clear()
    # Lancer sniff() dans un thread séparé
    sniff_thread = threading.Thread(target=lancer_sniff, daemon=True)
    sniff_thread.start()

# --- Fonctionnalité : Arrêter la capture de paquets ---
def SniffStop():
    Btn2.config(state="disabled")
    Btn.config(state="normal")
    stop_sniff_event.set()

# --- Fonctionnalité : Sauvegarder les paquets capturés dans un fichier PCAP ---
def save_packets():
    if ListPaquet:
        filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if filename:
            wrpcap(filename, ListPaquet)
            messagebox.showinfo("Sauvegarde", f"{len(ListPaquet)} paquets sauvegardés dans {filename}")
    else:
        messagebox.showwarning("Sauvegarde", "Aucun paquet à sauvegarder.")

#--- Fonctionnalité : entree lance la recherche ---
def on_enter(event):
    search_packets()

# --- Fonctionnalité : Recherche de paquets capturés ---
def search_packets():
    keyword = search_entry.get().lower()
    ScanList.delete(0, END)
    for i, pkt in enumerate(ListPaquet):
        summary = pkt.summary().lower()
        if keyword in summary:
            capture_time = time.strftime("%H:%M:%S", time.localtime())
            display_text = f"[{capture_time}] {pkt.summary()}"
            ScanList.insert(END, display_text)

# --- Fonctionnalité : Importer un fichier PCAP pour analyse hors ligne ---
def import_pcap():
    filename = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
    if filename:
        try:
            packets = rdpcap(filename)
            ListPaquet.clear()
            ScanList.delete(0, END)
            for pkt in packets:
                traiter(pkt)
            messagebox.showinfo("Import", f"{len(packets)} paquets importés depuis {filename}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'importation : {e}")


# fenetre principal
fenetre = Tk()
fenetre.title("Analyseur HTTP - Simple Packet Sniffer")
fenetre.geometry("900x650")
fenetre.configure(bg="#f8f8ff")
fenetre.resizable(width=True, height=True)
fenetre.iconbitmap("")  

# Menu en haut
Container = Frame(fenetre, relief=GROOVE, bd=2, padx=10, pady=8, bg="#f0f0f0")
Container.pack(fill=X, padx=10, pady=8)

# ---- Contrôle de fonctionnalité ---
ContainerBtn = LabelFrame(Container, relief=GROOVE, text="Contrôle", padx=8, pady=4, bg="#e6e6e6", font=("Arial", 10, "bold"))
ContainerBtn.grid(row=0, column=0, sticky="w", padx=5)

# Demarrer
Btn = Button(ContainerBtn, text="Démarrer", bg="#5F8F61", fg="white", padx=12, pady=6, font=("Arial", 10, "bold"), command=SniffStart, relief=RAISED, cursor="hand2")
Btn.grid(row=0, column=1, padx=5, pady=2)

# Arrêter
Btn2 = Button(ContainerBtn, text="Arrêter", bg="#883731", fg="white", padx=12, pady=6, font=("Arial", 10, "bold"), command=SniffStop, state="disabled", relief=RAISED, cursor="hand2")
Btn2.grid(row=0, column=2, padx=5, pady=2)

# Sauvegarde
BtnSave = Button(ContainerBtn, text="Sauvegarder", bg="#71899C", fg="white", padx=12, pady=6, font=("Arial", 10, "bold"), command=save_packets, relief=RAISED, cursor="hand2")
BtnSave.grid(row=0, column=3, padx=5, pady=2)

# Importer PCAP
BtnImport = Button(ContainerBtn, text="Importer PCAP", bg="#4D435E", fg="white", padx=12, pady=6, font=("Arial", 10, "bold"), command=import_pcap, relief=RAISED, cursor="hand2")
BtnImport.grid(row=0, column=4, padx=5, pady=2)

# realtime traffic
BtnTraffic = Button(ContainerBtn, text="Traffic en temps reel", bg="#94387D", fg="white", padx=12, pady=6, font=("Arial", 10, "bold"), command=show_realtime_traffic, relief=RAISED, cursor="hand2")
BtnTraffic.grid(row=0, column=5, padx=5, pady=2)

# Statistiques
BtnStatistics = Button(ContainerBtn, text="Statistiques", bg="#4A90E2", fg="white", padx=12, pady=6, font=("Arial", 10, "bold"), command=ouvrir_fenetre_stat, relief=RAISED, cursor="hand2")
BtnStatistics.grid(row=0, column=6, padx=5, pady=2)


search_frame = Frame(fenetre, bg="#f8f8ff")
search_frame = Frame(fenetre, bg="#f8f8ff")
search_frame.pack(fill=X, padx=10, pady=2)
Label(search_frame, text="Recherche :", bg="#f8f8ff").pack(side=LEFT)
search_entry = Entry(search_frame, width=30)
search_entry.pack(side=LEFT, padx=5)
search_entry.bind("<Return>", on_enter)
search_btn = Button(search_frame, text="Rechercher", command=search_packets) #Pour lancer la recherche en appuyant sur la touche Entrée
search_btn.pack(side=LEFT, padx=5)

#Vue de summary
VuePrincipal = LabelFrame(fenetre, text="Les paquets capturés", font=("Arial", 11, "bold"), relief=GROOVE, height="200px")
VuePrincipal.pack(fill=BOTH, padx=10, pady=8)

ScanView = Scrollbar(VuePrincipal)
ScanView.pack(side=RIGHT, fill=Y)
ScanList = Listbox(VuePrincipal, yscrollcommand=ScanView.set)
ScanList.pack(side=LEFT, fill=BOTH, expand=True)
ScanList.bind('<<ListboxSelect>>', on_select)
ScanView.config(command=ScanList.yview)

VueSecondaire = LabelFrame(fenetre, relief=GROOVE, pady=8, text="Information sur le paquet", font=("Arial", 11, "bold"), bg="#f0f4ff")
VueSecondaire.pack(fill=BOTH, padx=10, pady=8)

# Couche réseau (IP)
IpView = LabelFrame(
    VueSecondaire,
    relief=GROOVE,
    text="Ip Info",
    padx=8,
    pady=6,
    font=("Arial", 10, "bold"),
    bg="#e6f7ff"
)
IpView.grid(row=0, column=0, sticky="nsew", padx=8, pady=4)
IpInfo = Listbox(
    IpView,
    font=("Consolas", 10),
    width=30,
    height=10,
    bg="#f8f8ff",
    fg="#333"
)
IpInfo.pack(fill=BOTH, expand=True, padx=4, pady=2)

# Couche transport (TCP)
TcpView = LabelFrame(
    VueSecondaire,
    relief=GROOVE,
    text="TCP Info",
    padx=8,
    pady=6,
    font=("Arial", 10, "bold"),
    bg="#e6ffe6"
)
TcpView.grid(row=0, column=1, sticky="nsew", padx=8, pady=4)
TcpInfo = Listbox(
    TcpView,
    font=("Consolas", 10),
    width=30,
    height=10,
    bg="#f8f8ff",
    fg="#333"
)
TcpInfo.pack(fill=BOTH, expand=True, padx=4, pady=2)

# Couche application (HTTP)
HttpView = LabelFrame(
    VueSecondaire,
    relief=GROOVE,
    text="HTTP Info",
    padx=8,
    pady=6,
    font=("Arial", 10, "bold"),
    bg="#f7f7f7"
)
HttpView.grid(row=0, column=2, sticky="nsew", padx=8, pady=4)

# Pour une meilleure répartition des colonnes
VueSecondaire.grid_columnconfigure(0, weight=1)
VueSecondaire.grid_columnconfigure(1, weight=1)
VueSecondaire.grid_columnconfigure(2, weight=1)

# Scrollbar verticale
scrollbar = Scrollbar(HttpView)
scrollbar.pack(side=RIGHT, fill=Y)

# Text widget avec largeur et hauteur fixes
HttpInfo = Text(HttpView, wrap=WORD, yscrollcommand=scrollbar.set, width=45, height=10)
HttpInfo.pack(side=LEFT, fill=BOTH, expand=True)

scrollbar.config(command=HttpInfo.yview)

#boucle infini pour afficher la fenetre
fenetre.mainloop()
