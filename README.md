# Analyse des journaux d'un pare-feu

**Auteur :** Ramata Diallo

Projet 1 (L3) : analyse d'une semaine de connexions enregistrées par un pare-feu,
pour décrire l'activité du réseau et repérer les comportements suspects.

## Lancer le projet

Installer les dépendances :

```bash
pip install -r requirements.txt
```

Lancer l'analyse depuis la racine du dépôt :

```bash
python analyse.py
```

Le script lit `data/logs_reseau.csv`, nettoie les données, écrit `resultats.json`
et enregistre les graphiques dans `figures/`.

## Rapport

Les résultats et les recommandations sont présentés dans `rapport.md`.
