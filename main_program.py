import tkinter as tk
from tkinter import messagebox, ttk, Checkbutton, IntVar, Toplevel, Label, Button
import security_functions as sec

root = tk.Tk()
root.title("Toolbox")
root.geometry("300x200+600+600")  # Fenêtre principale

# Variables globales pour suivre la position de la dernière fenêtre
last_window_x = root.winfo_x()
last_window_y = root.winfo_y()

# Fonction utilitaire pour centrer les fenêtres
def center_window(window):
    global last_window_x, last_window_y

    root.update_idletasks()  # Assurez-vous que la taille de la fenêtre de référence est mise à jour

    width = window.winfo_width()
    height = window.winfo_height()

    # Positionner la nouvelle fenêtre à droite de la dernière fenêtre
    new_x = last_window_x + 300  # Ajouter la largeur de la fenêtre principale
    new_y = root.winfo_y()

    window.geometry(f"{width}x{height}+{new_x}+{new_y}")

    # Mettre à jour les positions pour la prochaine fenêtre
    last_window_x = new_x

# Variable globale pour stocker les résultats du scan
scan_results = {}

def display_scan_results(scan_results):
    result_window = tk.Toplevel(root)
    result_window.title("Résultats du Scan")

    # Configuration du style pour augmenter l'espace entre les lignes
    style = ttk.Style()
    style.configure("Treeview", rowheight=40)  # Augmente la hauteur des lignes

    tree = ttk.Treeview(result_window, columns=('Host', 'Status', 'Protocol', 'Port', 'Service', 'Version', 'CVE'), show='headings', style="Treeview")
    tree.heading('Host', text='Host')
    tree.heading('Status', text='Status')
    tree.heading('Protocol', text='Protocol')
    tree.heading('Port', text='Port')
    tree.heading('Service', text='Service')
    tree.heading('Version', text='Version')
    tree.heading('CVE', text='CVE')

    tree.column('Host', anchor='w', stretch=tk.YES)
    tree.column('Status', anchor='w', stretch=tk.YES)
    tree.column('Protocol', anchor='w', stretch=tk.YES)
    tree.column('Port', anchor='w', stretch=tk.YES)
    tree.column('Service', anchor='w', stretch=tk.YES)
    tree.column('Version', anchor='w', stretch=tk.YES)
    tree.column('CVE', anchor='w', stretch=tk.YES)

    # Pour éviter les doublons, on utilise un ensemble pour suivre les entrées déjà ajoutées
    added_entries = set()

    for host, info in scan_results.items():
        for proto, services in info['protocols'].items():
            for service in services:
                entry = (host, info['status'], proto, service['port'], service['service'], service['version'])
                if entry not in added_entries:
                    added_entries.add(entry)
                    cve_list = ", ".join([cve[0] for cve in service.get('cves', [])])
                    tree.insert('', 'end', values=(
                        host, 
                        info['status'], 
                        proto, 
                        service['port'], 
                        service['service'], 
                        service['version'],
                        cve_list
                    ))

    tree.pack(side="top", fill="both", expand=True)
    center_window(result_window)  # Positionner la fenêtre

def scan_ports():
    def on_scan():
        host = ip_entry.get()
        if host:
            global scan_results
            new_scan = sec.scan_services_and_versions(host)
            for proto, services in new_scan[host]['protocols'].items():
                for service in services:
                    service['cves'] = sec.search_cves(service['service'], service['version'])
                    print(f"Service: {service['service']} Version: {service['version']} CVEs: {service['cves']}")  # Debugging print statement
            scan_results.update(new_scan)
            display_scan_results(scan_results)
        scan_window.destroy()
    
    scan_window = tk.Toplevel(root)
    scan_window.title("Scan de Ports")
    
    tk.Label(scan_window, text="Entrez l'adresse IP à scanner:").pack()
    ip_entry = tk.Entry(scan_window)
    ip_entry.pack()
    
    tk.Button(scan_window, text="Scanner", command=lambda: on_scan()).pack()
    
    center_window(scan_window)  # Positionner la fenêtre

def analyze_password():
    def on_analyze():
        print("Analyse démarrée")  # Débogage: confirme que la fonction est appelée
        password = password_entry.get()
        if password:
            results = sec.analyze_password_security(password)

            # Mettre à jour l'interface utilisateur avec les résultats
            result_text = f"Force: {results['password_strength']}\nRetour: {results['password_feedback']}\n"
            if results['compromised']:
                result_text += f"Compromis: Oui, {results['times_compromised']} fois"
            else:
                result_text += "Compromis: Non"
            messagebox.showinfo("Résultats de l'Analyse", result_text)

            print("Analyse terminée")  # Débogage: indique que l'analyse est terminée

        else:
            print("Aucun mot de passe saisi")  # Débogage: aucun mot de passe saisi
        # analyze_window.destroy()  # Considérez de commenter cette ligne lors des tests pour éviter la fermeture de la fenêtre

    analyze_window = tk.Toplevel(root)
    analyze_window.title("Analyse de Sécurité des Mots de Passe")
    
    tk.Label(analyze_window, text="Entrez le mot de passe à analyser:").pack()
    password_entry = tk.Entry(analyze_window, show='*')
    password_entry.pack()
    
    tk.Button(analyze_window, text="Analyser", command=on_analyze).pack()

    center_window(analyze_window)  # Positionner la fenêtre

def test_authentication(auth_type):
    def on_test():
        use_dictionary = dictionary_var.get()
        host = ip_entry.get()
        username = username_entry.get()
        password = password_entry.get()  # Assurez-vous que ce champ est collecté si nécessaire pour l'authentification simple

        if use_dictionary:
            success = sec.perform_dictionary_attack(host, auth_type)
            result_message = "Connexion réussie." if success else "Aucun mot de passe valide trouvé."
            messagebox.showinfo("Résultat de l'Attaque par Dictionnaire", result_message)
        elif host and username and password:  # Assurez-vous que le mot de passe est également fourni
            if auth_type == 'FTP':
                success = sec.test_ftp_login(host, username, password)
            elif auth_type == 'SSH':
                success = sec.test_ssh_login(host, username, password)
            result_message = "Connexion réussie." if success else "Connexion échouée."
            messagebox.showinfo("Résultat du Test d'Authentification", result_message)
        else:
            messagebox.showwarning("Erreur", "Veuillez fournir toutes les informations requises.")
        auth_window.destroy()

    auth_window = tk.Toplevel(root)
    auth_window.title(f"Test d'Authentification {auth_type}")

    tk.Label(auth_window, text="Entrez l'adresse IP:").pack()
    ip_entry = tk.Entry(auth_window)
    ip_entry.pack()

    tk.Label(auth_window, text="Entrez le nom d'utilisateur:").pack()
    username_entry = tk.Entry(auth_window)
    username_entry.pack()

    tk.Label(auth_window, text="Entrez le mot de passe:").pack()  # Assurez-vous d'ajouter ce champ si nécessaire
    password_entry = tk.Entry(auth_window, show='*')
    password_entry.pack()

    dictionary_var = IntVar()
    Checkbutton(auth_window, text="Attaque par dictionnaire", variable=dictionary_var).pack()

    tk.Button(auth_window, text="Tester", command=on_test).pack()

    center_window(auth_window)  # Positionner la fenêtre

def on_generate_report():
    report_window = tk.Toplevel(root)
    report_window.title("Générer Rapport PDF")

    tk.Label(report_window, text="Entrez le nom du fichier de rapport:").pack()
    filename_entry = tk.Entry(report_window)
    filename_entry.pack()

    def generate():
        filename = filename_entry.get().strip()
        if filename:
            sec.generate_pdf_report(filename, scan_results)  # Assurez-vous que cette fonction et les données nécessaires sont accessibles
            report_window.destroy()
        else:
            messagebox.showwarning("Erreur", "Veuillez entrer un nom de fichier.")

    tk.Button(report_window, text="Générer", command=generate).pack()
    
    center_window(report_window)  # Positionner la fenêtre

tk.Button(root, text="Scan de Ports", command=scan_ports).pack(fill='x')
tk.Button(root, text="Analyse de Sécurité des Mots de Passe", command=analyze_password).pack(fill='x')
tk.Button(root, text="Test d'Authentification FTP", command=lambda: test_authentication('FTP')).pack(fill='x')
tk.Button(root, text="Test d'Authentification SSH", command=lambda: test_authentication('SSH')).pack(fill='x')
tk.Button(root, text="Générer Rapport PDF", command=on_generate_report).pack(fill='x')
tk.Button(root, text="Quitter", command=root.quit).pack(fill='x')

root.mainloop()
