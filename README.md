# Analyseur HTTP (CustomTkinter + Scapy)

Un outil simple d'analyse du trafic HTTP/HTTPS (port 80/8080/9000 configurés) avec une interface graphique moderne basée sur CustomTkinter, capturant et affichant les paquets en temps réel. Les données utiles sont archivées (JSON par IP) et des statistiques sont maintenues en SQLite.

## Fonctionnalités
- Capture de paquets (Scapy) avec filtre par ports (80/8080/9000) dans un thread séparé
- Liste des paquets capturés avec horodatage
- Détails par paquet: IP (src/dst, flags, ttl, etc.), TCP, et contenu HTTP brut
- Recherche plein texte sur les résumés des paquets
- Import d'un fichier PCAP pour analyse hors-ligne
- Sauvegarde des paquets en PCAP
- Export des données affichées (dans le code historique) et enregistrements JSON groupés par IP source
- Compteur SQLite du nombre de connexions par IP
- Graphique du trafic en temps réel (Matplotlib)
- UI modernisée avec CustomTkinter

## Prérequis
- Linux avec Python 3.12+ recommandé
- Droits de capture réseau (sudo ou capacités libpcap selon votre système)

## Installation rapide
1) Cloner le dépôt
```bash
git clone https://github.com/andrianemanantsoa/analyserhttp.git
cd analyserhttp/PythonReseau
```

2) Créer et activer un environnement virtuel
```bash
python3 -m venv .venv
source .venv/bin/activate
```

3) Installer les dépendances
```bash
pip install -r requirements.txt
```

Si vous préférez installer à la main:
```bash
pip install customtkinter scapy matplotlib
```

## Lancer l'application
Si vous devez capturer le trafic en direct, les droits root peuvent être nécessaires:
```bash
sudo -E .venv/bin/python main.py
```

Sinon (lecture de PCAP, test d'UI):
```bash
.venv/bin/python main.py
```

Astuce: pour éviter sudo, vous pouvez autoriser scapy/libpcap à capturer sans root via les capacités Linux (à adapter à votre distribution).

## Utilisation
- Démarrer/Arrêter: boutons en haut (capture en arrière-plan)
- Importer PCAP: charge un fichier et remplit la liste
- Recherche: saisir un mot-clé puis Entrée ou cliquer « Rechercher » (insensible à la casse)
	- Exemples: "http", "get", "syn", une IP comme "192.168.1.1"
- Sélection d’un paquet: affiche les détails IP/TCP/HTTP
- Sauvegarder: écrit tous les paquets capturés dans un .pcap
- Statistiques: ouvre la fenêtre de stats (voir `statistique.py`)
- Trafic temps réel: ouvre un graphe mis à jour chaque seconde

## Données persistées
- JSON par IP (fichiers `X.X.X.X.json`): contenu HTTP (payload) indexé par timestamp
- SQLite (`Ip_data`): table `ip_info(ip_addr, nb_conn)` mise à jour lors des requêtes HTTP (GET/POST)

## Dépannage
- ImportError: assurez-vous que l’environnement virtuel est activé et les paquets installés
- Capture vide sans erreurs: lancer avec sudo ou ajuster les filtres Scapy dans `lancer_sniff()`
- Affichage graphique bloqué: vérifiez que Matplotlib utilise bien TkAgg (défaut avec CustomTkinter)

## Développement
- Code principal: `main.py`
- Statistiques: `statistique.py`
- Exemples de JSON générés: fichiers `*.json` à la racine du projet
- Fichiers PCAP d’exemple: `*.pcap`

Contributions et améliorations sont les bienvenues.