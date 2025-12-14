# log-analyzer
Realisation d'un log-analyzer pour ma formation en cyber chez jedha

# 🛡️ CyberLog Analyzer — Mon premier outil de détection d'attaques

> **Disclaimer** : Je suis en formation cybersécurité chez Jedha. Ce projet a été réalisé dans le cadre de mon apprentissage. Le code n'est pas parfait, la méthode non plus, mais ça fonctionne et j'ai appris plein de trucs en le faisant. Si t'es débutant aussi, j'espère que ce retour d'expérience t'aidera !

---

## 🎯 C'est quoi ce projet ?

Un outil qui analyse des fichiers de logs Apache/Nginx pour détecter automatiquement :
- Les tentatives d'attaques **XSS** (Cross-Site Scripting)
- Les tentatives d'**injection SQL**
- Les **IPs suspectes** qui reviennent souvent

Au début c'était un simple script Python en ligne de commande. À la fin, c'est devenu une application desktop avec interface graphique que je peux lancer en double-cliquant. Le chemin entre les deux a été... intéressant.

---

## 🤔 Pourquoi ce projet ?

En formation, on passe du temps à lire des logs. Beaucoup de logs. Des milliers de lignes qui ressemblent à ça :

```
192.168.1.100 - - [10/Dec/2024:14:32:15 +0100] "GET /page?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0..."
```

C'est là que je suis arriver au point de la formation ou justement on me demande 
de creer un analyzer de log et c'est la que demarre cette histoire :
---

## 📝 Étape 1 — Comprendre ce qu'on manipule

Avant de coder, il fallait que je comprenne la structure d'une ligne de log. Voici ce qu'on y trouve :

| Élément | Exemple | Description |
|---------|---------|-------------|
| IP | `192.168.1.100` | Qui a fait la requête |
| Timestamp | `[10/Dec/2024:14:32:15]` | Quand |
| Requête | `"GET /page?id=1 HTTP/1.1"` | Quoi |
| Status | `200` | Résultat (200 = OK) |
| User-Agent | `"Mozilla/5.0..."` | Avec quel navigateur |

Mon premier objectif : extraire chacun de ces éléments.

---

## 🔨 Étape 2 — Parser les logs

"Parser" = découper une chaîne de caractères pour en extraire les infos utiles.

```python
def parse_log_line(log_line):
    # L'IP c'est facile, c'est le premier mot
    parts = log_line.split(" ")
    ip = parts[0]
    
    # Le timestamp est entre crochets [ ]
    start = log_line.find("[")
    end = log_line.find("]")
    timestamp = log_line[start+1:end]
    
    # La requête est entre les premiers guillemets " "
    first_quote = log_line.find('"')
    second_quote = log_line.find('"', first_quote + 1)
    request = log_line[first_quote+1:second_quote]
    
    # Le status code est juste après la requête
    after_request = log_line[second_quote+1:]
    parts_after = after_request.split()
    status_code = parts_after[0]
    
    # Le User-Agent est la dernière chaîne entre guillemets
    last_quote = log_line.rfind('"')
    second_last_quote = log_line.rfind('"', 0, last_quote)
    user_agent = log_line[second_last_quote+1:last_quote]

    return {
        'ip': ip,
        'timestamp': timestamp,
        'request': request,
        'status_code': status_code,
        'user_agent': user_agent
    }
```

### Ce que j'ai appris

- `find()` trouve la position d'un caractère (en partant du début)
- `rfind()` fait pareil mais en partant de la fin
- `split()` découpe une chaîne en liste

Est-ce que c'est la méthode la plus élégante ? Probablement pas. On pourrait utiliser des regex. Mais ça marche, je comprends ce que ça fait, et c'est ce qui compte quand on apprend.

---

## 🔍 Étape 3 — Détecter les attaques XSS

Une attaque XSS essaie d'injecter du JavaScript. Dans les logs, ça ressemble à :

```
GET /search?q=<script>alert('pwned')</script>
GET /page?img=<img onerror=alert(1)>
```

Ma stratégie : chercher des mots-clés suspects.

```python
def detect_xss_attacks(parsed_logs):
    xss_attacks = []
    xss_patterns = [
        '<script>', 
        'alert(', 
        'onerror=', 
        'javascript:', 
        '<img', 
        '<iframe', 
        'onload='
    ]

    for log in parsed_logs:
        request = log['request'].lower()
        
        for pattern in xss_patterns:
            if pattern in request:
                xss_attacks.append(log)
                break
    
    return xss_attacks
```

### Les limites (je suis honnête)

Cette détection est basique. Un attaquant peut contourner en :
- Encodant les caractères (`<script>` → `%3Cscript%3E`)
- Jouant sur les majuscules (`<ScRiPt>`)
- Utilisant des techniques plus avancées

Pour un vrai outil de production, il faudrait améliorer ça. Mais pour comprendre le principe et s'entraîner, c'est suffisant.

---

## 💉 Étape 4 — Détecter les injections SQL

Même principe :

```python
def detect_sql_injection(parsed_logs):
    sql_attacks = []
    sql_patterns = [
        "' or '1'='1", 
        "or 1=1", 
        "union select", 
        "'--", 
        "'; drop table", 
        "admin'--",
        "select * from"
    ]
    
    for log in parsed_logs:
        request = log['request'].lower()
        
        for pattern in sql_patterns:
            if pattern in request:
                sql_attacks.append(log)
                break
    
    return sql_attacks
```

---

## 🖥️ Étape 5 — Version ligne de commande

À ce stade, j'avais un script utilisable :

```bash
python log_analyzer.py access.log
```

Résultat :

```
============================================================
RAPPORT RÉCAPITULATIF
============================================================
📂 Fichier analysé : access.log
📝 Lignes analysées : 1547
🔍 Attaques XSS : 12
💉 Injections SQL : 8
🎯 TOTAL MENACES : 20
============================================================

🚨 IPs malveillantes détectées : 3
  ⚠️  192.168.1.105
  ⚠️  10.0.0.42
  ⚠️  172.16.0.99
```

Satisfaisant ! Mais je me suis dit : et si je faisais une interface graphique ?

---

## ✨ Étape 6 — L'interface graphique

J'ai choisi **CustomTkinter** — une librairie Python qui permet de faire des interfaces modernes assez facilement.

### Galère n°1 : l'installation sur Mac

```bash
pip install customtkinter
```

Réponse :

```
error: externally-managed-environment
× This environment is externally managed
```

macOS avec Homebrew refuse d'installer des packages Python "dans le vide". Il faut créer un environnement virtuel :

```bash
python3 -m venv ~/cyberlog-env
source ~/cyberlog-env/bin/activate
pip install customtkinter
```

### Galère n°2 : Tkinter manquant

Je lance le script :

```bash
python3 cyberlog_analyzer.py
```

Nouvelle erreur :

```
ModuleNotFoundError: No module named '_tkinter'
```

Python via Homebrew n'inclut pas Tkinter par défaut. Solution :

```bash
brew install python-tk@3.14
```

### Enfin, ça marche !

Après ces deux corrections, l'interface s'est lancée. Le design est inspiré de l'esthétique "cybersécurité" — fond sombre, accents cyan et violet.

L'app propose :
- Un bouton pour charger un fichier log
- L'analyse automatique avec détection XSS et SQLi
- 4 onglets pour voir les résultats filtrés
- Des statistiques en temps réel
- Un export du rapport

---

## 📦 Étape 7 — Créer une vraie application

Taper des commandes dans un terminal à chaque fois, c'est pas pratique. Je voulais une icône sur laquelle cliquer.

**PyInstaller** permet de transformer un script Python en application :

```bash
source ~/cyberlog-env/bin/activate
pip install pyinstaller
pyinstaller --onefile --windowed --name "CyberLog" cyberlog_analyzer.py
```

Résultat : un fichier `CyberLog.app` dans le dossier `dist/`.

```bash
mv dist/CyberLog.app /Applications/
```

Et voilà, j'ai une vraie app dans mon Launchpad !

---

## 🛠️ Installation complète (pour reproduire)

### Prérequis
- Python 3.10+
- Mac, Linux ou Windows

### Étapes

```bash
# 1. Sur Mac, installer Tkinter
brew install python-tk@3.14

# 2. Créer l'environnement virtuel
python3 -m venv ~/cyberlog-env
source ~/cyberlog-env/bin/activate

# 3. Installer CustomTkinter
pip install customtkinter

# 4. Lancer l'application
python3 cyberlog_analyzer.py
```

### Créer l'exécutable (optionnel)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "CyberLog" cyberlog_analyzer.py
mv dist/CyberLog.app /Applications/
```

---

## 📁 Structure du projet

```
cyberlog-analyzer/
├── cyberlog_analyzer.py    # L'application
├── README.md               # Ce fichier
└── samples/
    └── access.log          # Fichier de test
```

---

## 🧠 Ce que j'ai appris

**Techniquement :**
- Manipuler des fichiers et des chaînes en Python
- Détecter des patterns d'attaques
- Créer une interface graphique
- Packager une application

**Plus généralement :**
- Les erreurs font partie du process
- Commencer simple, améliorer ensuite
- Documenter ses galères aide les autres (et soi-même dans 6 mois)

---

## 🚀 Améliorations possibles

- [ ] Décoder les URL avant analyse
- [ ] Détecter le path traversal (`../`)
- [ ] Mode "temps réel" pour surveiller un fichier
- [ ] Export PDF
- [ ] Icône personnalisée

---

## 📜 Licence

MIT — Utilise-le, modifie-le, améliore-le !

---

## 👤 Auteur

**Matthieu** — En formation cybersécurité chez Jedha, en route vers le pentest.

*Ce projet est perfectible, comme moi. Si t'as des suggestions ou des questions, n'hésite pas !*

