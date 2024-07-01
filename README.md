# Toolbox de Pentest

## Introduction

Bienvenue dans OP-CyberSecuTools, votre nouvel allié dans le monde de la cybersécurité ! Développée dans le cadre de mon Master en Cybersécurité, cette boîte à outils a été pensée pour rendre les tests d'intrusion aussi simples qu'efficaces.

Imaginez pouvoir automatiser vos scans de sécurité en quelques clics et obtenir un rapport PDF complet et bien structuré, tout cela sans avoir à être un expert en cybersécurité. C'est exactement ce que OP-CyberSecuTools vous offre. En utilisant des scripts Python robustes comme main_program.py et security_functions.py, notre outil consolide les résultats de divers scans pour vous fournir une vue d'ensemble claire et actionnable de votre sécurité.

Fonctionnant parfaitement sous Linux, cette application est accessible à tous, même sans connaissances préalables en cybersécurité. Et pour ceux qui connaissent déjà un peu le domaine, vous apprécierez d'autant plus la précision et la profondeur des analyses fournies.

Prêt à découvrir les vulnérabilités cachées de votre système et à les gérer efficacement ? OP-CyberSecuTools est là pour vous aider.

## Fonctionnalités

### Scan Nmap
L'outil s'intègre avec Nmap pour effectuer des scans réseau et recueillir des informations sur les ports ouverts, les services et les versions. Il collecte également les CVE (Common Vulnerabilities and Exposures) associées en utilisant l'API de la NVD (National Vulnerability Database).

### Analyse de Sécurité des Mots de Passe
Cette fonctionnalité analyse la sécurité des mots de passe en utilisant la bibliothèque zxcvbn. Elle évalue la force des mots de passe et vérifie s'ils ont été compromis en utilisant l'API Have I Been Pwned.

### Test d'Authentification FTP et SSH
L'outil permet de tester les authentifications FTP et SSH en utilisant des attaques par dictionnaire. Il utilise Hydra pour effectuer ces attaques, testant différentes combinaisons de noms d'utilisateur et de mots de passe.

### Génération de Rapport PDF
Tous les résultats collectés sont compilés dans un rapport PDF, y compris les résultats de chaque scan et test effectué précédemment.

## Prérequis
- **Python** : Assurez-vous que Python est installé sur votre système.
- **pip** : Assurez-vous que pip est installé pour la gestion des packages Python.
- **Nmap** : Téléchargez et installez Nmap depuis [nmap.org](https://nmap.org/).
- **Hydra** : Téléchargez et installez Hydra depuis le site officiel ou via votre gestionnaire de paquets.
- **Curl** : Téléchargez et installez Curl pour récupérer les fichiers de dictionnaire.
- **Zxcvbn** : La bibliothèque zxcvbn pour analyser la force des mots de passe.
- **ReportLab** : Utilisé pour générer des rapports PDF.
- **Paramiko** : Utilisé pour les connexions SSH.
- **Requests** : Pour les requêtes HTTP utilisées dans l'outil.
- **Ftplib** : Pour les connexions FTP.


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


## Structure du Projet
```
toolbox/
├── main_program.py
├── security_functions.py
├── requirements.txt
├── reports/
│   ├── report.pdf
├── wordlists/
│   ├── usernames.txt
│   ├── rockyou.txt
└── README.md
├── __pycache__
```

## Utilisation
### Lancer l'application:
Pour démarrer l'application, exécutez le script main_program.py. Ce script sert de point d'entrée pour la toolbox.
```bash
python main_program.py
```

### Naviguer dans le menu :
À l'ouverture de l'application, vous accéderez à la page d'accueil, puis en cliquant sur le bouton "Start", vous accéderez au menu principal. Ce menu vous permet de naviguer entre les différentes fonctionnalités de la toolbox.

## Fonctionnalités détaillées
### Scan de Ports avec Nmap
- **Accéder à la page Nmap**: Depuis le menu principal, accédez à la page "Scan de Ports".
- **Entrer les informations de la cible**: Saisissez l'adresse IP de la cible à scanner.
- **Lancer le scan** : Démarrez le scan Nmap. Les résultats s'afficheront dans la fenêtre de l'application et seront sauvegardés pour inclusion dans le rapport PDF.

### Analyse de Sécurité des Mots de Passe
- **Accéder à la page d'analyse des mots de passe** : Depuis le menu principal, accédez à la page "Analyse de Sécurité des Mots de Passe".
- **Entrer le mot de passe** : Saisissez le mot de passe à analyser.
- **Lancer l'analyse**: Démarrez l'analyse. Les résultats s'afficheront dans une fenêtre de message.
### Test d'Authentification FTP et SSH
- **Accéder à la page d'authentification** : Depuis le menu principal, accédez à la page "Test d'Authentification FTP" ou "Test d'Authentification SSH".
- **Entrer les informations de la cible** : Saisissez l'adresse IP de la cible et le nom d'utilisateur.
- **Entrer les listes d'identifiants et de mots de passe** : Fournissez les fichiers de dictionnaire usernames.txt et rockyou.txt.
- **Lancer le test** : Démarrez l'attaque par force brute. Les résultats s'afficheront dans une fenêtre de message et seront sauvegardés pour inclusion dans le rapport PDF.
### Génération du Rapport PDF
- **Accéder à la page de génération du rapport**: Depuis le menu principal, accédez à la page "Générer Rapport PDF".
- **Générer le rapport** : Cliquez sur le bouton pour générer le rapport PDF. Le rapport compilera toutes les données collectées dans un document structuré incluant les résultats de tous les scans et tests effectués.

