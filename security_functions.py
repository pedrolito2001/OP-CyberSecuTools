import nmap
import ftplib
import paramiko
import requests
import hashlib
from zxcvbn import zxcvbn
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.platypus.flowables import PageBreak
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from datetime import datetime
import json
import subprocess
import os

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = "ff976256-546b-4117-9a83-3de1b1953128"

# Variable globale pour stocker les résultats d'Hydra
hydra_results = []

# Fonction pour scanner les services et versions
def scan_services_and_versions(host):
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-sV')
    scan_results = {}
    for host in nm.all_hosts():
        scan_results[host] = {
            'status': nm[host].state(),
            'protocols': {}
        }
        for proto in nm[host].all_protocols():
            scan_results[host]['protocols'][proto] = []
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]
                service_info = {
                    'port': port,
                    'service': service['name'],
                    'version': service.get('product', '') + " " + service.get('version', '')
                }
                if service_info not in scan_results[host]['protocols'][proto]:
                    scan_results[host]['protocols'][proto].append(service_info)
    return scan_results

# Fonction pour rechercher des CVE en utilisant l'API NVD 2.0
def search_cves(service, version):
    cves = []
    query = f"{service} {version}".strip()
    headers = {'apiKey': NVD_API_KEY}
    params = {'keywordSearch': query, 'resultsPerPage': 10}  # Limite à 10 résultats pour l'exemple
    try:
        response = requests.get(NVD_API_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            if 'vulnerabilities' in data:
                for item in data['vulnerabilities']:
                    cve_id = item['cve']['id']
                    description = item['cve'].get('descriptions', [{'value': 'No description available'}])[0]['value']
                    recommendations = item['cve'].get('references', [{'url': 'No remediation available'}])[0]['url']
                    cves.append((cve_id, description, recommendations))
            else:
                print(f"No CVE items found in response for query: {query}")
        else:
            print(f"Error fetching CVEs: {response.status_code} {response.text}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response for query: {query}, error: {e}")
    except Exception as e:
        print(f"Unexpected error fetching CVEs: {e}")

    # Si aucune CVE trouvée avec la recherche combinée, effectuer une recherche uniquement par version
    if not cves and version:
        query = version.strip()
        params = {'keywordSearch': query, 'resultsPerPage': 10}  # Limite à 10 résultats pour l'exemple
        try:
            response = requests.get(NVD_API_URL, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data:
                    for item in data['vulnerabilities']:
                        cve_id = item['cve']['id']
                        description = item['cve'].get('descriptions', [{'value': 'No description available'}])[0]['value']
                        recommendations = item['cve'].get('references', [{'url': 'No remediation available'}])[0]['url']
                        cves.append((cve_id, description, recommendations))
                else:
                    print(f"No CVE items found in response for query: {query}")
            else:
                print(f"Error fetching CVEs: {response.status_code} {response.text}")
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON response for query: {query}, error: {e}")
        except Exception as e:
            print(f"Unexpected error fetching CVEs: {e}")

    return cves

# Fonction pour tester l'authentification FTP
def test_ftp_login(host, username, password):
    try:
        ftp = ftplib.FTP(host)
        ftp.login(username, password)
        ftp.quit()
        return True
    except ftplib.all_errors:
        return False

# Fonction pour tester l'authentification SSH
def test_ssh_login(host, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except paramiko.SSHException as e:
        print(f"SSH error: {e}")
        return False

# Utilisation de Hydra pour l'attaque par dictionnaire SSH et FTP
def perform_dictionary_attack(host, auth_type):
    base_path = os.path.join(os.path.dirname(__file__), 'wordlists')
    user_dictionary_file = os.path.join(base_path, 'usernames.txt')
    password_dictionary_file = os.path.join(base_path, 'french_passwords_top20000.txt')
    
    if auth_type == 'FTP':
        try:
            print(f"Lancement de Hydra pour FTP avec les fichiers {user_dictionary_file} et {password_dictionary_file}")
            result = subprocess.run([
                'hydra', '-L', user_dictionary_file, '-P', password_dictionary_file, '-t', '4', '-f', host, 'ftp'
            ], capture_output=True, text=True)
            print(f"Hydra output: {result.stdout}")
            print(f"Hydra errors: {result.stderr}")
            if "login:" in result.stdout:
                print(f"Connexion réussie: {result.stdout}")
                for line in result.stdout.splitlines():
                    if "login:" in line:
                        parts = line.split()
                        username_index = parts.index("login:") + 1
                        password_index = parts.index("password:") + 1
                        username = parts[username_index]
                        password = parts[password_index]
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        hydra_results.append((username, password, timestamp, 'FTP'))
                return True
        except Exception as e:
            print(f"Erreur lors de l'utilisation de Hydra: {e}")
    elif auth_type == 'SSH':
        try:
            print(f"Lancement de Hydra pour SSH avec les fichiers {user_dictionary_file} et {password_dictionary_file}")
            result = subprocess.run([
                'hydra', '-L', user_dictionary_file, '-P', password_dictionary_file, '-t', '4', '-f', host, 'ssh'
            ], capture_output=True, text=True)
            print(f"Hydra output: {result.stdout}")
            print(f"Hydra errors: {result.stderr}")
            if "login:" in result.stdout:
                print(f"Connexion réussie: {result.stdout}")
                for line in result.stdout.splitlines():
                    if "login:" in line:
                        parts = line.split()
                        username_index = parts.index("login:") + 1
                        password_index = parts.index("password:") + 1
                        username = parts[username_index]
                        password = parts[password_index]
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        hydra_results.append((username, password, timestamp, 'SSH'))
                return True
        except Exception as e:
            print(f"Erreur lors de l'utilisation de Hydra: {e}")
    
    print("Aucun mot de passe valide trouvé.")
    return False

# Fonction pour analyser la sécurité d'un mot de passe
def analyze_password_security(password):
    results = zxcvbn(password)
    strength = results['score']
    feedback = results['feedback']['warning'] + " " + ' '.join(results['feedback']['suggestions'])
    compromised, times_compromised = check_if_compromised(password)
    return {
        'password_strength': strength,
        'password_feedback': feedback,
        'compromised': compromised,
        'times_compromised': times_compromised
    }

def check_if_compromised(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    response = requests.get(url)
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return True, int(count)
    return False, 0

def summarize_text(text, max_length=300):
    if len(text) > max_length:
        return text[:max_length] + "..."
    else:
        return text

def generate_pdf_report(filename, scan_results):
    base_path = os.path.join(os.path.dirname(__file__), 'reports')
    if not os.path.exists(base_path):
        os.makedirs(base_path)
        
    filename = os.path.join(base_path, f"{filename}.pdf")
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []

    styles = getSampleStyleSheet()
    title_style = styles['Title']
    title_style.fontSize = 18
    title_style.leading = 22

    subtitle_style = styles['Heading2']
    subtitle_style.fontSize = 16
    subtitle_style.leading = 20

    heading_style = styles['Heading3']
    heading_style.fontSize = 14
    heading_style.leading = 18

    normal_style = styles['Normal']
    normal_style.fontSize = 10
    normal_style.leading = 12

    small_style = ParagraphStyle(
        name='Small',
        fontSize=8,
        leading=10,
        textColor=colors.black,
        alignment=TA_JUSTIFY
    )

    title = Paragraph('Rapport de Sécurité', title_style)
    generated_on = Paragraph(f'Généré le: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}', normal_style)

    # Variables pour déterminer s'il y a des vulnérabilités ou des résultats d'attaque
    has_vulnerabilities = any(service.get('cves') for host in scan_results.values() for protocol in host['protocols'].values() for service in protocol)
    has_hydra_results = bool(hydra_results)

    if has_vulnerabilities or has_hydra_results:
        introduction_title = Paragraph('Introduction:', subtitle_style)
        introduction = Paragraph(
            "Ce rapport vise à présenter les vulnérabilités identifiées suite à un scan de sécurité. "
            "Les informations suivantes détaillent les services détectés, les versions associées, ainsi que les vulnérabilités (CVE) trouvées. "
            "Des recommandations sont également fournies pour remédier à ces vulnérabilités.",
            normal_style
        )

        elements.append(title)
        elements.append(generated_on)
        elements.append(Spacer(1, 12))
        elements.append(introduction_title)
        elements.append(Spacer(1, 6))
        elements.append(introduction)
        elements.append(Spacer(1, 12))

        for host, info in scan_results.items():
            elements.append(Paragraph(f'Host: {host}', subtitle_style))
            elements.append(Spacer(1, 12))
            data = [['Port', 'Service', 'Version', 'CVE']]
            for protocol, services in info['protocols'].items():
                for service in services:
                    cve_list = ', '.join([cve[0] for cve in service.get('cves', [])])
                    data.append([service['port'], Paragraph(service['service'], normal_style), Paragraph(service['version'], normal_style), Paragraph(cve_list, normal_style)])
            
            table = Table(data, colWidths=[50, 100, 150, 250])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 24))  # Ajouter de l'espace après chaque tableau

        # Ajout du titre pour la section des descriptions des CVE
        elements.append(Paragraph('Description des CVE:', subtitle_style))
        elements.append(Spacer(1, 12))

        # Ajout de descriptions et recommandations pour chaque CVE
        cve_data = [['CVE ID', 'Description', 'Recommandations']]
        for host, info in scan_results.items():
            for protocol, services in info['protocols'].items():
                for service in services:
                    if 'cves' in service:
                        for cve in service['cves']:
                            cve_data.append([cve[0], Paragraph(summarize_text(cve[1]), small_style), Paragraph(cve[2], small_style)])

        cve_table = Table(cve_data, colWidths=[100, 250, 150], repeatRows=1)
        cve_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(cve_table)
        elements.append(Spacer(1, 24))  # Ajouter de l'espace après chaque tableau

        # Ajouter les résultats Hydra après les résultats du scan de ports
        if has_hydra_results:
            elements.append(Paragraph('Résultats de l\'attaque par dictionnaire Hydra:', subtitle_style))
            elements.append(Paragraph(
                "Les résultats ci-dessous montrent les tentatives d'attaque par dictionnaire réussies. "
                "Veuillez vérifier les informations et prendre les mesures nécessaires pour sécuriser les services.",
                normal_style
            ))
            elements.append(Spacer(1, 12))  # Saut de ligne entre le texte explicatif et le tableau

            hydra_data = [['Utilisateur', 'Mot de passe', 'Heure', 'Type']]
            for result in hydra_results:
                hydra_data.append([result[0], result[1], result[2], result[3]])
            
            hydra_table = Table(hydra_data, colWidths=[100, 100, 150, 100])
            hydra_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(hydra_table)
            elements.append(Spacer(1, 24))

        # Ajout de la conclusion
        conclusion_title = Paragraph('Conclusion:', subtitle_style)
        conclusion_text = Paragraph(
            "Le présent rapport a permis de mettre en lumière plusieurs vulnérabilités présentes dans les services et versions détectés sur les hôtes analysés. "
            "Les CVE identifiées montrent une gamme de risques potentiels qui doivent être traités pour améliorer la sécurité globale de l'infrastructure. "
            "<br/><br/>"
            "<b>Principales recommandations :</b>"
            "<br/>"
            "1. <b>Mises à jour et correctifs</b> : Assurez-vous que tous les logiciels et services sont à jour avec les derniers correctifs de sécurité. Les versions obsolètes des services sont souvent les plus vulnérables aux attaques."
            "<br/>"
            "2. <b>Renforcement des configurations</b> : Appliquez des configurations de sécurité renforcées pour les services critiques. Désactivez les services non utilisés pour réduire la surface d'attaque."
            "<br/>"
            "3. <b>Surveillance continue</b> : Mettez en place des systèmes de surveillance pour détecter et alerter rapidement en cas d'activités suspectes. Une surveillance proactive peut aider à prévenir les incidents de sécurité."
            "<br/>"
            "4. <b>Audits réguliers</b> : Effectuez des audits de sécurité réguliers pour identifier et corriger les nouvelles vulnérabilités. Les audits fréquents permettent de maintenir un haut niveau de sécurité."
            "<br/>"
            "5. <b>Formation et sensibilisation</b> : Assurez-vous que le personnel est formé et conscient des meilleures pratiques en matière de sécurité informatique. Une formation adéquate peut réduire les erreurs humaines qui sont souvent à l'origine des incidents de sécurité."
            "<br/><br/>"
            "En suivant ces recommandations et en traitant les vulnérabilités identifiées dans ce rapport, vous pouvez améliorer considérablement la posture de sécurité de votre organisation. "
            "Une attention continue à la sécurité et une mise en œuvre diligente des correctifs et des améliorations sont essentielles pour protéger vos actifs numériques contre les menaces en constante évolution. "
            "Pour toute question ou assistance supplémentaire, n'hésitez pas à contacter notre équipe de sécurité.",
            normal_style
        )
        elements.append(conclusion_title)
        elements.append(Spacer(1, 6))
        elements.append(conclusion_text)
        elements.append(Spacer(1, 12))

    else:
        introduction_title = Paragraph('Introduction:', subtitle_style)
        introduction = Paragraph(
            "Ce rapport vise à présenter les résultats d'un scan de sécurité. "
            "Les informations suivantes montrent que tous les services et versions détectés sont sécurisés et ne présentent aucune vulnérabilité connue.",
            normal_style
        )

        elements.append(title)
        elements.append(generated_on)
        elements.append(Spacer(1, 12))
        elements.append(introduction_title)
        elements.append(Spacer(1, 6))
        elements.append(introduction)
        elements.append(Spacer(1, 12))

        elements.append(Paragraph('Conclusion:', subtitle_style))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(
            "Le scan de sécurité n'a révélé aucune vulnérabilité critique sur les hôtes analysés. Les services et versions détectés semblent être correctement configurés et sécurisés. "
            "Il est néanmoins recommandé de maintenir une surveillance continue et de réaliser des audits réguliers pour garantir que la sécurité reste au plus haut niveau. "
            "Bravo pour vos efforts de sécurité continus et continuez à suivre les meilleures pratiques pour maintenir un environnement sécurisé. "
            "Pour toute question ou assistance supplémentaire, n'hésitez pas à contacter notre équipe de sécurité.",
            normal_style
        ))
        elements.append(Spacer(1, 12))

    doc.build(elements)
    print(f"Rapport généré sous le nom : {filename}")
