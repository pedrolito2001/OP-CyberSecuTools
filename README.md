# OP-CyberSecuTools

## Introduction

Bienvenue dans OP-CyberSecuTools, votre nouvel allié dans le monde de la cybersécurité ! Développée dans le cadre de mon Master en Cybersécurité, cette boîte à outils a été pensée pour rendre les tests d'intrusion aussi simples qu'efficaces.

Imaginez pouvoir automatiser vos scans de sécurité en quelques clics et obtenir un rapport PDF complet et bien structuré, tout cela sans avoir à être un expert en cybersécurité. C'est exactement ce que OP-CyberSecuTools vous offre. En utilisant des scripts Python robustes comme main_program.py et security_functions.py, notre outil consolide les résultats de vos analyses pour vous offrir une vue d'ensemble claire et exploitable de votre sécurité.

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
- **Attaques par Dictionnaire** En utilisant Hydra, l'outil peut effectuer des attaques par dictionnaire pour tester une large gamme de combinaisons de noms d'utilisateur et de mots de passe automatiquement. Par défaut, les fichiers de dictionnaire username_test_list.txt et password_test_list.txt, situés dans le dossier wordlists, sont utilisés pour améliorer les performances. Les fichiers de dictionnaire plus volumineux usernames.txt et rockyou.txt restent également disponibles dans le dossier wordlists et peuvent être utilisés en modifiant les lignes 134 et 135 dans le fichier security_functions.py.

### Génération de Rapport PDF
Tous les résultats collectés sont compilés dans un rapport PDF complet. Ce rapport inclut :
- **Introduction** : Présente les objectifs et le contexte du rapport.
- **Détails des Hôtes** : Liste les hôtes scannés avec leurs adresses IP.
- **Résultats des Scans** : Inclut les services détectés sur chaque port avec les versions et les CVE associées.
- **Description des CVE** : Fournit des descriptions détaillées des vulnérabilités trouvées, accompagnées de liens vers des ressources pour plus d'informations.
- **Résultats des Tests d'Authentification** : Présente les résultats des attaques par dictionnaire, incluant les noms d'utilisateur et mots de passe trouvés.
- **Conclusion** : Résume les principales vulnérabilités découvertes et propose des recommandations pour remédier à ces faiblesses, comme la mise à jour des logiciels, le renforcement des configurations, la surveillance continue, les audits réguliers, et la formation du personnel.
- **Rapport alternatif** : Si aucune CVE n'est détectée, le rapport généré indique que tous les services et versions détectés sont sécurisés et ne présentent aucune vulnérabilité connue. La conclusion recommandera néanmoins de maintenir une surveillance continue et de réaliser des audits réguliers pour garantir que la sécurité reste au plus haut niveau.

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
cd OP-CyberSecuTools/
```
### Installer les packages requis :
```bash
pip install -r requirements.txt
```


## Structure du Projet
```
OP-CyberSecuTools/
├── main_program.py
├── security_functions.py
├── requirements.txt
├── reports/
│   ├── test-projet.pdf
├── wordlists/
│   ├── usernames.txt
│   ├── french_passwords_top20000.txt
│   ├── password_test_list.txt
│   ├── username_test_list.txt
└── README.md
```

## Utilisation: 
### Lancer l'application:
Pour démarrer l'application, exécutez le script main_program.py. Ce script sert de point d'entrée pour la toolbox.
```bash
python main_program.py
```

### Naviguer dans le menu :
À l'ouverture de l'application, vous accéderez directement au menu principal. Ce menu vous permet de naviguer entre les différentes fonctionnalités de la toolbox :
* Scan de Ports
* Analyse de Sécurité des Mots de Passe
* Test d'Authentification FTP
* Test d'Authentification SSH
* Générer Rapport PDF
* Quitter

## Fonctionnalités détaillées
### Scan de Ports
- **Accéder à la page Scan de Ports** : Depuis le menu principal, sélectionnez l'option "Scan de Ports".
- **Entrer les informations de la cible** : Saisissez l'adresse IP de la cible à scanner.
- **Lancer le scan** : Démarrez le scan en cliquant sur le bouton "Scanner".
- **Visualiser les résultats** : Une fois le scan terminé, une fenêtre avec un tableau s'affichera, montrant les résultats du scan. Ces résultats seront stockés et sauvegardés pour inclusion dans le rapport PDF.

### Analyse de Sécurité des Mots de Passe
* Accéder à la page d'analyse des mots de passe : Depuis le menu principal, accédez à la page "Analyse de Sécurité des Mots de Passe".
* Entrer le mot de passe : Saisissez le mot de passe à analyser.
* Lancer l'analyse : Cliquez sur le bouton pour démarrer l'analyse. Les résultats de l'analyse s'afficheront dans une fenêtre de message, incluant :
  * La force du mot de passe
  * Des recommandations pour améliorer la sécurité
  * Le nombre de fois que le mot de passe a été compromis
### Test d'Authentification FTP et SSH
L'outil permet de tester les authentifications FTP et SSH de manière flexible :
* **Accéder à la page d'authentification** : Depuis le menu principal, sélectionnez l'option "Test d'Authentification FTP" ou "Test d'Authentification SSH".
* **Tests Manuels** :
  * **Entrer les informations de la cible** : Saisissez l'adresse IP de la cible.
  * **Entrer les identifiants** : Saisissez le nom d'utilisateur et le mot de passe.
  * **Lancer le test** : Cliquez sur le bouton pour tester l'accès manuellement. Les résultats s'afficheront dans une fenêtre de message et seront sauvegardés pour inclusion dans le rapport PDF.

* **Attaques par Dictionnaire** : En utilisant Hydra, l'outil peut effectuer des attaques par dictionnaire automatiquement.
  * **Entrer les informations de la cible** : Saisissez l'adresse IP de la cible.
  * **Lancer le test** : Cliquez sur le bouton "Attaque par Dictionnaire" pour démarrer l'attaque. Les fichiers de dictionnaire `username_test_login.txt` et `password_test_login.txt` sont sélectionnés automatiquement. Les résultats des connexions réussies s'afficheront dans une fenêtre de message et seront sauvegardés pour inclusion dans le rapport PDF.
### Génération du Rapport PDF
* **Accéder à la page de génération du rapport** : Depuis le menu principal, sélectionnez l'option "Générer Rapport PDF".
* **Générer le rapport** : Cliquez sur le bouton pour générer le rapport PDF. Le rapport compilera toutes les données collectées, incluant :
  * Un résumé des scans et des analyses effectuées.
  * Des détails sur les vulnérabilités découvertes.
  * Des descriptions des CVE associées.
  * Les résultats des tests d'authentification.
  * Des recommandations pour corriger les vulnérabilités.



Fait par Pedro SOUSA ORTEGA de la classe : MSI 4-25 CS A ISI PARIS
