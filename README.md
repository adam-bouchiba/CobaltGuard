# CobaltGuard

Application Windows open source d'audit de sécurité, développée en Python.
Cette première version affiche l'état de Microsoft Defender et des trois profils
du pare-feu Windows dans une interface CustomTkinter sombre, futuriste et épurée.

Les collectes sont **en lecture seule**, sans élévation automatique de droits.
Les résultats restent sur le PC, avec des exports TXT (Bloc-notes) et JSON facultatifs à la demande.
Aucun envoi réseau ni journal persistant n'est implémenté dans cette version.

## Télécharger une version Windows portable

Une **construction automatique Windows x64** produit un fichier
`CobaltGuard-windows-x64.zip` après le passage des tests.

- Dans **Actions → Windows beta** : ouvrir une exécution réussie et télécharger
  l'artifact `CobaltGuard-windows-x64`, puis extraire l'archive ZIP.
- Quand une version est publiée : la télécharger depuis **Releases** (le tag
  `v0.1.0` n'est pas créé automatiquement pour éviter une publication non testée).
- Dans le dossier extrait, lancer `CobaltGuard.exe`. Python n'est pas requis.
  **Ne pas** déplacer le fichier EXE seul : les bibliothèques du dossier sont nécessaires.

**Important :** ce programme est une **bêta non signée**. Windows SmartScreen
peut avertir que l'éditeur n'est pas reconnu. N'exécutez pas un programme dont
la provenance ou l'archive vous semble douteuse. Nous recommandons de vérifier
la provenance GitHub et de tester l'application d'abord sur une machine de test.

Instructions de création d'une release et checklist : [distribution Windows](docs/distribution.md).

## Installer et lancer sous Windows

Cible initiale : **Windows 11 x64, Python 3.12 avec Tcl/Tk**, et Windows PowerShell
5.1 fourni par Windows. Les dépendances Python sont téléchargées à l'installation.
L'application ne nécessite pas PowerShell 7.

Depuis PowerShell, dans le dossier du dépôt :

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m cobaltguard
```

L'environnement `.venv` isole les dépendances de ce projet. L'option `-e`
installe le projet en mode éditable : modifier les sources modifie le programme
lancé, sans réinstallation. L'option `[dev]` ajoute pytest pour les tests.
Pour utiliser seulement l'application, `pip install -e .` suffit.

Ces commandes utilisent directement le Python du venv : aucune activation de
script ni modification de la politique d'exécution PowerShell n'est nécessaire.
Si `py` est absent, utiliser le chemin du Python 3.12 installé.

Cliquer sur **Lancer l'analyse**. Aucun contrôle ne démarre à l'ouverture.
Le bouton est désactivé pendant la collecte ; la fenêtre reste utilisable.
Les deux contrôles s'exécutent successivement dans un thread de travail, avec
un délai maximal de 15 secondes par processus PowerShell.

## Tableau de bord et rapports

L'interface sombre noir/violet affiche un état de collecte, trois compteurs
(nombre de contrôles, résultats conformes, éléments à examiner) et des cartes
de résultats repliables. Les statuts `UNKNOWN` et `ERROR` restent à examiner :
ils ne sont **jamais** comptés comme des contrôles conformes.

Après l'analyse, les actions suivantes sont disponibles :

- **Exporter le rapport TXT** : choisir le chemin d'un fichier `.txt` lisible
  par le Bloc-notes Windows, avec la synthèse, les constats et les recommandations.
- **Exporter le rapport JSON** : enregistrer les données structurées pour
  les analyser par programme.
- **Ouvrir dans Bloc-notes** : disponible uniquement après avoir enregistré
  un rapport TXT ; ouvre exactement le fichier choisi.

L'application ne crée **aucun** fichier automatiquement lors du scan, et ne
transmet aucun résultat à un serveur. Les fichiers TXT sont encodés en UTF-8
avec BOM pour un affichage fiable des accents dans les éditeurs Windows.

Les rapports peuvent révéler des informations locales ou des messages d'erreur :
**les relire et les anonymiser avant toute publication ou partage**.

## Lire les résultats

| Statut | Signification |
| --- | --- |
| `PASS` | Toutes les données requises sont présentes et les critères du contrôle sont satisfaits. |
| `WARNING` | Un état mérite une vérification contextualisée, par exemple un mode Defender passif. |
| `FAIL` | Une protection vérifiée est désactivée ; lire les détails et vérifier si cet état est attendu. |
| `UNKNOWN` | Les informations sont absentes, incomplètes, non reconnues ou inaccessibles. |
| `ERROR` | Une erreur technique a empêché le contrôle : délai dépassé, commande échouée ou JSON invalide. |

Un résultat ne constitue ni une preuve de compromission ni une garantie de
sécurité globale. Si un problème est observé mais que d'autres informations
manquent, le `FAIL` ou `WARNING` reste affiché avec la mention **Contrôle incomplet**.

**Microsoft Defender :** le contrôle lit le service, la fonction antivirus,
la protection en temps réel, l'âge des signatures et le mode de fonctionnement.
Le seuil d'avertissement au-delà de 7 jours pour les signatures est une heuristique
locale, pas une règle officielle Microsoft. Un mode passif ou EDR produit un
avertissement : il ne démontre ni l'absence ni l'efficacité d'un antivirus tiers.

**Pare-feu :** le contrôle consulte les profils Domaine, Privé et Public dans
la stratégie active. Il ne détermine pas le profil réseau actuellement utilisé
et n'évalue pas les règles. La valeur Windows `NotConfigured` reste inconnue ;
elle n'est pas convertie en « activé ».

Une commande absente ou un accès refusé donne `UNKNOWN`. L'autre contrôle reste
exécuté. Vérifier les informations manuellement dans **Sécurité Windows** ;
l'application ne demande pas automatiquement de droits administrateur.

## Comprendre les fichiers

```text
pyproject.toml                 Dépendances et configuration pytest
src/cobaltguard/
    __main__.py               Lancement avec python -m cobaltguard
    models.py                 Status et CheckResult, contrat partagé
    services.py               Coordination des contrôles et de leurs erreurs
    windows/powershell.py     Collectes fixes, processus, délais, décodage JSON
    checks/defender.py        Interprétation pure des observations Defender
    checks/firewall.py        Interprétation pure des profils du pare-feu
    gui/app.py                Widgets, thread de travail, affichage et export
    reporting/json_report.py  Export JSON optionnel des résultats
    reporting/text_report.py  Export TXT lisible dans le Bloc-notes
tests/unit/
    test_defender.py          Réponses Defender simulées
    test_firewall.py          Profils simulés, informations manquantes et ambiguës
    test_powershell.py        Simulation du processus et de ses erreurs
    test_services.py          Audit complet avec un faux collecteur
    test_text_report.py       Rapport TXT (statuts, contenu et horodatage)
docs/architecture.md          Explication des choix et du flux d'exécution
docs/distribution.md          Processus de distribution, limites et vérifications
packaging/launcher.py         Point d'entrée PyInstaller
.github/workflows/windows-beta.yml   Tests et build Windows automatiques
```

Les `__init__.py` marquent les packages Python. Aucun fichier du moteur n'importe
CustomTkinter. Les règles reçoivent des données, pas des widgets ni des processus.
Lire [l'explication de l'architecture](docs/architecture.md) pour suivre le trajet
d'un clic jusqu'au résultat.

## Vérifier cette version

Exécuter les tests sans modifier la configuration du PC :

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Les tests simulent notamment une protection désactivée, un mode passif, des
signatures anciennes, des profils manquants, un accès refusé et une expiration
du délai. Il n'est pas nécessaire de désactiver ses protections pour les tester.
Les cas paramétrés exécutent une même règle avec plusieurs réponses.

Sur un poste Windows, effectuer ensuite ce contrôle manuel :

1. Lancer l'application en utilisateur standard et vérifier qu'aucune demande
   d'élévation n'apparaît.
2. Cliquer sur le bouton, déplacer ou redimensionner la fenêtre pendant l'analyse
   et vérifier que le bouton empêche un second lancement simultané.
3. Vérifier que deux résultats apparaissent, que les cartes se déplient et que les compteurs sont cohérents.
4. Comparer les informations disponibles à **Sécurité Windows → Protection contre
   les virus et menaces** et **Pare-feu et protection réseau**. Un refus d'accès
   doit être explicite, jamais affiché comme `PASS`.
5. Exporter en TXT, puis ouvrir le fichier dans le Bloc-notes et vérifier ses accents.
6. Exporter en JSON et vérifier que le contenu reste valide.
7. Relancer l'analyse : les cartes doivent être remplacées, pas dupliquées.

La fenêtre peut être fermée pendant une analyse. Le thread termine les collectes
restantes en arrière-plan avant la sortie du processus Python, afin de laisser
les délais PowerShell interrompre et nettoyer leurs processus si nécessaire.
Cela peut prendre environ 30 secondes, plus le temps de démarrage des processus.

### Développement sous Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

Les tests métier fonctionnent sans Windows, sans interface et sans privilèges.
Ouvrir l'interface demande Tcl/Tk et un affichage graphique. Sur Linux, les
collectes réelles retournent `UNKNOWN` avec l'explication « nécessite Windows ».

Les tests simulés ne valident pas les commandes natives sur Windows. Les essais
Windows décrits ci-dessus restent nécessaires avant d'annoncer cette compatibilité
comme vérifiée.

## Périmètre actuel

Cette étape comprend uniquement l'interface, Defender, le pare-feu et leurs tests.
Le scanner de fichiers, le chiffrement et l'analyse du démarrage restent pour
les étapes ultérieures. Les exports TXT/JSON et une construction Windows automatisée
sont maintenant disponibles, mais cette archive bêta doit encore être validée
manuellement sur Windows avant une diffusion large.

Licence : [MIT](LICENSE).
