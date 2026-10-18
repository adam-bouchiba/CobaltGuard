# Distribution Windows (bêta)

## Source

Le point d'entrée `packaging/launcher.py` importe l'application existante.
La configuration utilise **PyInstaller** et `--onedir` pour inclure les
bibliothèques et ressources de CustomTkinter sans modifier le moteur d'audit.

Sur Windows 11 x64, depuis la racine du dépôt :

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e . "pyinstaller>=6,<7"
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --onedir --windowed --name CobaltGuard --collect-all customtkinter packaging/launcher.py
.\dist\CobaltGuard\CobaltGuard.exe
```

Ne pas distribuer le seul exécutable. Tout le dossier `dist/CobaltGuard`
fait partie de l'application.

## GitHub Actions et Releases

Le workflow `.github/workflows/windows-beta.yml` :

1. Lance les tests Python sur Linux et Windows.
2. Construit l'application sur le runner Windows x64 si les tests passent.
3. Produit une archive `CobaltGuard-windows-x64.zip` comme artifact Actions.
4. Publie une **prerelease GitHub** seulement lorsqu'un tag `v*` est poussé.

Après validation manuelle et fusion dans `main` :

```powershell
git checkout main
git pull
git tag v0.1.0
git push origin v0.1.0
```

Ne pas réutiliser un tag existant : incrémenter la version pour chaque publication.

## Validation manuelle indispensable

À réaliser sur un PC ou une VM **Windows 11 x64** avant diffusion :

- Télécharger l'archive produite, l'extraire entièrement et lancer l'EXE.
- Vérifier qu'aucun Python ni droit administrateur ne sont demandés.
- Lancer l'audit et comparer Defender/pare-feu avec Sécurité Windows.
- Tester le mode Defender passif et les informations manquantes, sans désactiver
  les protections de sa propre machine.
- Exporter un rapport dans un dossier autorisé, vérifier le JSON et refuser
  l'enregistrement pour tester l'annulation.
- Fermer la fenêtre pendant la collecte, puis la relancer.
- Vérifier les faux positifs et tester sur une deuxième machine Windows.

## Confiance et limites

Le binaire est **non signé** : SmartScreen peut afficher un avertissement
de réputation. Ne contournez pas aveuglément les alertes de sécurité.
La provenance du dépôt et de l'archive doit être vérifiée.

Les tests unitaires ne remplacent pas les tests Windows ni un audit du package.
Le programme n'examine pas encore les fichiers suspects, n'est pas un antivirus,
ne corrige pas les réglages et ne garantit pas l'absence de compromission.

Les informations exportées peuvent être privées. L'application n'envoie
aucun résultat à un serveur ; ne publiez jamais un rapport brut par défaut.
