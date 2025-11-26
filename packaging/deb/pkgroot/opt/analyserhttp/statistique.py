import tkinter as tk
from tkinter import messagebox
import sqlite3
import json
import os
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def ouvrir_fenetre_stat():

    donnees_json = {}

    # === Interface ===
    stat_root = tk.Toplevel()  
    stat_root.title("Statistique des connexions")

    # Frame principale
    main_frame = tk.Frame(stat_root)
    main_frame.pack(fill="both", expand=True)

    # Gauche : Diagramme circulaire
    frame_gauche = tk.Frame(main_frame)
    frame_gauche.pack(side="left", padx=10, pady=10)

    # Droite : conteneur général
    frame_droite = tk.Frame(main_frame)
    frame_droite.pack(side="left", fill="both", expand=True, padx=10, pady=10)

    # --- Liste des timestamps avec scrollbar dédiée ---
    frame_ts_scroll = tk.Frame(frame_droite)
    frame_ts_scroll.pack(fill="both", expand=True)

    canvas_ts = tk.Canvas(frame_ts_scroll, height=200)
    scrollbar_ts = tk.Scrollbar(frame_ts_scroll, orient="vertical", command=canvas_ts.yview)
    canvas_ts.configure(yscrollcommand=scrollbar_ts.set)

    scrollbar_ts.pack(side="right", fill="y")
    canvas_ts.pack(side="left", fill="both", expand=True)

    frame_timestamps_inner = tk.Frame(canvas_ts)
    canvas_ts.create_window((0, 0), window=frame_timestamps_inner, anchor="nw")

    # Ajustement du scroll
    def on_frame_configure(event):
        canvas_ts.configure(scrollregion=canvas_ts.bbox("all"))

    frame_timestamps_inner.bind("<Configure>", on_frame_configure)

    # --- Zone texte avec scrollbar  ---

    label_details = tk.Label(frame_droite, text="Details", font=("Arial", 12, "bold"))
    label_details.pack(anchor="w", pady=(0, 2))
    frame_txt = tk.Frame(frame_droite)
    frame_txt.pack(fill="both", expand=True, pady=(10, 0))

    scrollbar_txt = tk.Scrollbar(frame_txt)
    zone_contenu = tk.Text(frame_txt, wrap="word", height=15, yscrollcommand=scrollbar_txt.set)
    scrollbar_txt.config(command=zone_contenu.yview)

    zone_contenu.pack(side="left", fill="both", expand=True)
    scrollbar_txt.pack(side="right", fill="y")

   
    def charger_donnees():
        conn = sqlite3.connect("Ip_data")
        cur = conn.cursor()
        cur.execute("SELECT ip_addr, nb_conn FROM ip_info")
        rows = cur.fetchall()
        conn.close()
        if not rows:
            return [], []
        labels = [row[0] for row in rows]
        sizes = [row[1] for row in rows]
        return labels, sizes

    def afficher_contenu(timestamp):
        contenu = donnees_json.get(timestamp, "")
        zone_contenu.delete("1.0", tk.END)
        zone_contenu.insert(tk.END, f"{timestamp}\n\n{contenu}")

    def afficher_fichier_json(ip):
        nonlocal donnees_json
        nom_fichier = f"{ip}.json"
        if not os.path.isfile(nom_fichier):
            messagebox.showwarning("Fichier manquant", f"Le fichier {nom_fichier} est introuvable.", parent=stat_root)
            return

        with open(nom_fichier, "r") as f:
            donnees_json = json.load(f)

        items_tries = sorted(donnees_json.items())

        # Nettoyage de la liste
        for widget in frame_timestamps_inner.winfo_children():
            widget.destroy()

        for timestamp, _ in items_tries:
            btn = tk.Button(frame_timestamps_inner, text=timestamp, anchor="w",
                            command=lambda ts=timestamp: afficher_contenu(ts))
            btn.pack(fill="x", pady=1)

    def onclick(event):
        if event.inaxes is None:
            return
        for i, wedge in enumerate(pie_patches):
            if wedge.contains_point((event.x, event.y)):
                ip_selectionnee = labels[i]
                afficher_fichier_json(ip_selectionnee)
                break

    
    def afficher_pie_chart():
        nonlocal pie_patches, labels
        labels, sizes = charger_donnees()

        if not labels:
            messagebox.showerror("Erreur", "Aucune donnée trouvée dans la base.", parent=stat_root)
            return

        fig = Figure(figsize=(5, 5), dpi=100)
        ax = fig.add_subplot(111)
        pie_patches, texts, autotexts = ax.pie(
            sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')

        canvas = FigureCanvasTkAgg(fig, master=frame_gauche)
        canvas.draw()
        canvas.get_tk_widget().pack()
        canvas.mpl_connect("button_press_event", onclick)

    # Initialisation du graphique
    pie_patches = []
    labels = []
    afficher_pie_chart()
