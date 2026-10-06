\# Intelligent Network Analyzer



\## Présentation



Intelligent Network Analyzer est un outil d'analyse défensive du trafic réseau.

Il permet de capturer du trafic réel, analyser les paquets, identifier les communications,

détecter certains comportements inhabituels, expliquer les observations et conserver

l'historique des analyses.



\## Fonctionnalités



\- Capture réseau réelle avec Scapy

\- Analyse IPv4 et IPv6

\- Analyse TCP, UDP et ICMP

\- Identification des ports et protocoles

\- Regroupement et suivi des communications

\- Détection de scans et anomalies

\- Moteur d'explication et recommandations

\- Enrichissement des IP publiques avec ipwho.is

\- Stockage et historique avec Supabase

\- Dashboard Web

\- Export JSON, CSV et PDF

\- Tests automatisés



\## Architecture



Capture réseau → Analyse → Communications → Détection

→ Enrichissement → Explication → Supabase → Dashboard



\## Technologies



Python 3.11, FastAPI, Scapy, Supabase, SQLite,

ReportLab, HTML, CSS, JavaScript et API ipwho.is.



\## Installation



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

pip install -r requirements.txt

