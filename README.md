# OP-CyberSecuTools

## Introduction

Bienvenue dans OP-CyberSecuTools, votre nouvel allié dans le monde de la cybersécurité ! Développée dans le cadre de mon Master en Cybersécurité, cette boîte à outils a été pensée pour rendre les tests d'intrusion aussi simples qu'efficaces.

Imaginez pouvoir automatiser vos scans de sécurité en quelques clics et obtenir un rapport PDF complet et bien structuré, tout cela sans avoir à être un expert en cybersécurité. C'est exactement ce que OP-CyberSecuTools vous offre. En utilisant des scripts Python robustes comme main_program.py et security_functions.py, notre outil consolide les résultats de divers scans pour vous fournir une vue d'ensemble claire et actionnable de votre sécurité.

Fonctionnant parfaitement sous Linux, cette application est accessible à tous, même sans connaissances préalables en cybersécurité. Et pour ceux qui connaissent déjà un peu le domaine, vous apprécierez d'autant plus la précision et la profondeur des analyses fournies.

Prêt à découvrir les vulnérabilités cachées de votre système et à les gérer efficacement ? OP-CyberSecuTools est là pour vous aider.

## Fonctionnalités

### Scan Nmap
L'outil s'intègre avec Nmap pour effectuer des scans réseau et recueillir des informations sur les ports ouverts, les services et les versions. Il collecte également les CVE (Common Vulnerabilities and Exposures) associées en utilisant l'API de la NVD (National Vulnerability Database)

### Analyse de Sécurité des Mots de Passe
Cette fonctionnalité analyse la sécurité des mots de passe en utilisant la bibliothèque zxcvbn. Elle évalue la force des mots de passe et vérifie s'ils ont été compromis en utilisant l'API Have I Been Pwned.

### Test d'Authentification FTP et SSH
L'outil permet de tester les authentifications FTP et SSH de manière flexible :

- **Tests Manuels** : Vous pouvez entrer des combinaisons de noms d'utilisateur et de mots de passe manuellement pour tester l'accès.
- **Attaques par Dictionnaire** : En utilisant Hydra, l'outil peut effectuer des attaques par dictionnaire pour tester une large gamme de combinaisons de noms d'utilisateur et de mots de passe automatiquement.

### Génération de Rapport PDF
Tous les résultats collectés sont compilés dans un rapport PDF complet. Ce rapport inclut :
- **Introduction** : Présente les objectifs et le contexte du rapport.
- **Détails des Hôtes** : Liste les hôtes scannés avec leurs adresses IP.
- **Résultats des Scans** : Inclut les services détectés sur chaque port avec les versions et les CVE associées.
- **Description des CVE** : Fournit des descriptions détaillées des vulnérabilités trouvées, accompagnées de liens vers des ressources pour plus d'informations.
- **Résultats des Tests d'Authentification** : Présente les résultats des attaques par dictionnaire, incluant les noms d'utilisateur et mots de passe trouvés.
- **Conclusion** : Résume les principales vulnérabilités découvertes et propose des recommandations pour remédier à ces faiblesses, comme la mise à jour des logiciels, le renforcement des configurations, la surveillance continue, les audits réguliers, et la formation du personnel.

## Prérequis
- **Python** : Langage de programmation utilisé pour développer l'application.
- **pip** : Outil de gestion des packages Python.
- **Nmap** : Utilisé pour effectuer des scans réseau.
- **Hydra** : Utilisé pour les attaques par dictionnaire sur les services d'authentification.
- **Curl** : Utilisé pour récupérer les fichiers de dictionnaire.
- **zxcvbn** : Utilisé pour analyser la force des mots de passe.
- **ReportLab** : Utilisé pour générer des rapports PDF.
- **Paramiko** : Utilisé pour les connexions SSH.
- **Requests** : Utilisé pour effectuer des requêtes HTTP.
- **ftplib** : Utilisé pour les connexions FTP.



## Installation

### Cloner le dépôt :
```bash
git clone https://github.com/pedrolito2001/OP-CyberSecuTools.git
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

