# Toolbox de Pentest

## Introduction

Bienvenue dans la Toolbox de Pentest, un projet développé dans le cadre de mon programme de Master en Cybersécurité.

Cet outil est conçu pour automatiser les tests de pénétration professionnels.

Il consolide les résultats de divers scans en un rapport PDF bien structuré, facilitant ainsi la révision et la gestion des vulnérabilités par les professionnels de la sécurité.

L'application a été développée en Python et fonctionne sous Windows, la rendant facilement accessible. Aucune connaissance préalable en cybersécurité n'est nécessaire pour utiliser l'application, bien que l'interprétation des résultats puisse être complexe sans cette connaissance.

## Fonctionnalités

### Scan Nmap
L'outil s'intègre avec Nmap pour effectuer des scans réseau et recueillir des informations sur les ports ouverts, les services et les versions. Il collecte également les CVE (Common Vulnerabilities and Exposures) associées en utilisant l'API de la NVD.

### Analyse de Sécurité des Mots de Passe
Cette fonctionnalité analyse la sécurité des mots de passe en utilisant la bibliothèque zxcvbn. Elle évalue la force des mots de passe et vérifie s'ils ont été compromis en utilisant l'API Have I Been Pwned.

### Test d'Authentification FTP et SSH
L'outil permet de tester les authentifications FTP et SSH en utilisant des attaques par dictionnaire. Il utilise Hydra pour effectuer ces attaques, testant différentes combinaisons de noms d'utilisateur et de mots de passe.

### Génération de Rapport PDF
Tous les résultats collectés sont compilés dans un rapport PDF, y compris les résultats de chaque scan et test effectué précédemment.

## Prérequis
- **Python** : Assurez-vous que Python (version 3.10 ou 3.11) est installé sur votre système.
  - ! Avertissement : La dernière version de Python 3.12 ne fonctionne pas avec cette Toolbox. Vous devez télécharger Python 3.11 depuis [python.org](https://www.python.org/) !
- **pip** : Assurez-vous que pip est installé pour la gestion des packages Python.
- **Nmap** : Téléchargez et installez Nmap depuis [nmap.org](https://nmap.org/).
- **Hydra** : Téléchargez et installez Hydra depuis le site officiel ou via votre gestionnaire de paquets.
- **Curl** : Téléchargez et installez Curl pour récupérer les fichiers de dictionnaire.

## Installation

### Cloner le dépôt :
```bash
git clone https://github.com/votre-utilisateur/votre-repo.git
cd votre-repo/
```
### Installer les packages requis :
```bash
pip install -r requirements.txt
```

##Structure du Projet
```
toolbox/
├── main_program.py
├── security_functions.py
├── requirements.txt
├── results/
│   ├── scan_results.json
│   ├── hydra_results.json
├── reports/
│   ├── report.pdf
├── wordlists/
│   ├── usernames.txt
│   ├── rockyou.txt
└── README.md
```

## Utilisation
### Lancer l'application:
Pour démarrer l'application, exécutez le script main_program.py. Ce script sert de point d'entrée pour la toolbox.
```bash
python main_program.py
```

