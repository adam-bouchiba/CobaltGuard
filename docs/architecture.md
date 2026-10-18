# Première étape : du clic au résultat

Le but de cette étape est d'obtenir une première chaîne complète et compréhensible :
une action dans l'interface déclenche deux collectes Windows, leurs observations
sont interprétées et les résultats sont affichés sans bloquer la fenêtre.

## 1. Un contrat commun, sans interface graphique

`models.py` définit deux objets :

- `Status`, une énumération, limite les valeurs aux cinq statuts convenus.
- `CheckResult`, une `dataclass` immuable, regroupe l'identifiant, le titre,
  le statut, le résumé, les observations et les recommandations.

Une dataclass évite d'écrire manuellement un constructeur répétitif. `frozen=True`
et les tuples empêchent de modifier un résultat après sa transmission au thread
graphique. L'interface n'a donc pas besoin de connaître la structure du JSON Windows.

Dans cette petite version, le statut décrit la conclusion du contrôle ; ce n'est
pas un niveau de gravité numérique. `UNKNOWN` signale l'impossibilité de conclure,
`ERROR` un problème technique. Aucun score global n'est calculé.

## 2. Le moteur coordonne, les règles interprètent

`AuditService.run()` dans `services.py` est volontairement synchrone : il exécute
Defender, puis le pare-feu. Il ne choisit pas comment l'application organise ses
threads et n'importe jamais de widget.

Son collecteur est injectable : en production, il reçoit un `PowerShellRunner` ;
en test, un petit faux collecteur offre la même méthode `run(query)`. Le `Protocol`
documente cette interface sans obliger le faux collecteur à hériter d'une classe.

Les fonctions `evaluate_defender` et `evaluate_firewall` sont pures : les mêmes
données produisent les mêmes résultats, sans appel système ni écriture. Elles
valident les types avant d'interpréter les valeurs. Exemple important : en Python,
`bool("false")` vaut `True` ; ce raccourci serait incorrect pour un audit.

Les contrôles suivent cette logique :

1. Valider les données et conserver les inconnues.
2. Rechercher les états défavorables confirmés.
3. Expliquer le statut, les observations et les limites.
4. Produire `PASS` uniquement si toutes les informations requises sont exploitables.

Un échec connu n'est pas masqué par une information manquante : la carte conserve
`FAIL` et précise qu'elle est incomplète. Une absence d'information, seule, ne
produit jamais `FAIL` ou `PASS`.

## 3. PowerShell est une frontière contrôlée

`windows/powershell.py` accepte une valeur de `PowerShellQuery`, jamais un script
fourni par l'interface. Les deux collectes autorisées sont :

```powershell
Get-MpComputerStatus -ErrorAction Stop
Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop
```

Le code sélectionne ensuite les propriétés nécessaires. Il convertit explicitement
`Enabled` du pare-feu en texte : il s'agit d'une énumération Windows `GpoBoolean`,
pas d'un simple booléen. Le tableau des profils est préservé même si PowerShell
renvoie zéro ou un seul élément.

Le processus est lancé avec :

- Le chemin système de Windows PowerShell, sans recherche d'exécutable dans `PATH`.
- `-NoProfile` et `-NonInteractive`, sans script de profil utilisateur ni prompt.
- Une liste d'arguments et `shell=False`, sans shell intermédiaire.
- Une sortie JSON encodée en UTF-8, pour éviter d'interpréter du texte localisé.
- Un délai de 15 secondes ; `subprocess.run` tue et attend le processus à expiration.

`$ErrorActionPreference = 'Stop'` et `-ErrorAction Stop` transforment les erreurs
PowerShell en exceptions interceptables. Le script renvoie soit les données,
soit une erreur structurée. Python contrôle également le code de sortie.

| Situation | Traduction par le service |
| --- | --- |
| Plateforme non Windows, PowerShell ou commande absente | `UNKNOWN` |
| Accès refusé | `UNKNOWN`, sans relance avec davantage de privilèges |
| JSON valide mais informations absentes ou non reconnues | Interprétation en `UNKNOWN` ou résultat partiel explicite |
| Délai dépassé, échec d'exécution ou JSON invalide | `ERROR` |

Les erreurs prévues sont traitées par contrôle : un échec Defender n'empêche pas
le pare-feu d'être interrogé. Aucun réglage n'est modifié, aucune politique
d'exécution n'est contournée et aucune commande d'élévation n'est utilisée.

## 4. La boucle graphique doit rester libre

Tkinter traite les clics et dessine la fenêtre dans son thread principal.
Y appeler directement une collecte lente figerait l'application.

Le parcours de l'analyse est donc :

```text
Thread principal                         Thread de travail
----------------                         -----------------
Clic → désactiver le bouton
     → démarrer le travailleur ----------> AuditService.run()
Boucle Tk toujours disponible              → collecte Defender et interprétation
     → after(100, ...)                     → collecte pare-feu et interprétation
     → consulter la Queue <-------------- tuple de CheckResult
     → créer les cartes
     → réactiver le bouton
```

`Queue` transporte les résultats de façon sûre entre threads. `after()` programme
une consultation courte de cette file dans la boucle Tk. Le travailleur ne fait
aucun appel Tk, même pour signaler une erreur.

Un dernier gestionnaire transforme une erreur Python inattendue en carte `ERROR`,
afin de rendre le bouton utilisable à nouveau. Ce filet de sécurité ne remplace
pas les exceptions précises du moteur.

À la fermeture, les callbacks sont annulés et les widgets détruits. Le travailleur
non daemon termine sa collecte sans toucher à la fenêtre ; Python attend sa fin.
Ce choix simple conserve le nettoyage des sous-processus par leur timeout.

## 5. Apprendre avec les tests

Lire les fichiers dans cet ordre :

1. `models.py`, puis `test_defender.py` : observer le contrat et les cas attendus.
2. `checks/defender.py`, puis `checks/firewall.py` : suivre les règles pures.
3. `windows/powershell.py` et `test_powershell.py` : comprendre la frontière système.
4. `services.py` et `test_services.py` : comprendre l'injection et l'indépendance des contrôles.
5. `gui/app.py` et `__main__.py` : suivre la circulation des résultats entre threads.

Les fixtures pytest produisent des réponses Windows simulées. `parametrize`
applique le même test à plusieurs valeurs ; `monkeypatch` et `Mock` remplacent
le lancement du processus. Aucun test unitaire n'affaiblit la sécurité du PC.

Ces tests prouvent le comportement Python face aux réponses prévues. La disponibilité
réelle des commandes, leurs permissions et le rendu natif nécessitent des essais
sur Windows, décrits dans le README.
