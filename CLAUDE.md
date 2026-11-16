# katello-inspector

Outil open source, en lecture seule, qui donne à un administrateur Katello une vue rapide de l'état de ses VMs, de leur retard de contenu et de la santé de la plateforme. Python 3.9+, bibliothèque standard uniquement, licence Apache 2.0.

Sources de vérité, à lire avant de coder :
- `docs/cadrage.md` : périmètre, sous-commandes, règles de statut, JSON, seuils, performances. C'est la spécification. Toute divergence passe par une mise à jour de ce document, pas par un choix silencieux.
- `docs/api-findings.md` : ce qui a été observé sur une vraie instance (Katello 4.21.1.1 / Foreman 3.19.1), chemins de champs exacts et pièges.
- `docs/fixtures.md` : quelles réponses enregistrer pour les tests et comment les anonymiser.

## Règles non négociables

1. **Lecture seule stricte.** Seules des requêtes HTTP GET partent du code, par une seule fonction (`api.py`). Un test automatique échoue si une autre méthode HTTP apparaît dans le code source.
2. **Bibliothèque standard uniquement** (urllib, configparser, argparse, json). Aucune dépendance d'exécution. pytest, ruff et mypy sont des dépendances de développement.
3. **Une information absente n'est jamais présentée comme saine.** Champ absent ou null : UNKNOWN avec la raison. N/A est réservé aux indicateurs qui ne s'appliquent pas. Jamais de valeur par défaut qui masque une absence.
4. **Le jeton** se lit dans un fichier ou une variable d'environnement, jamais en argument. Il n'apparaît dans aucun log, message d'erreur ni sortie JSON, y compris en débogage.
5. **TLS validé par défaut.** `--insecure` doit être explicite à chaque appel et signalé dans la sortie.
6. **Pas de shell, pas de sous-processus, pas d'`eval`/`exec`.**
7. **Codes retour.** Mode manuel : 0 si la commande s'est déroulée, 1 en cas d'erreur d'exécution, 2 en cas d'erreur d'usage. Mode `--monitoring` : convention Nagios 0/1/2/3, et toute défaillance de l'outil donne 3 (jamais 1 ou 2). Prévoir un gestionnaire central, car argparse renvoie 2 par défaut et une exception non interceptée renvoie 1.
8. **Séparer la collecte, l'analyse et l'affichage** (voir la structure du dépôt dans le cadrage). Ajouter un format de sortie ne doit pas toucher aux règles de statut.
9. **Pas d'appel par VM** dans `summary`, `list` et `content`. Les compteurs d'errata, le statut des traces et la version servie sont dans la liste des hôtes. Seul `host` fait quelques appels pour une VM.
10. **Aucune valeur propre à un environnement dans le dépôt** : noms de serveur, d'organisation, de CV ou de produits, adresses, jetons. Les exemples utilisent `katello.example.com` et des noms génériques.

## Pièges connus de l'API (détails dans docs/api-findings.md)

- Un champ de recherche inconnu sur `/api/hosts` renvoie **HTTP 500** (« not recognized for searching »), et 400 sur les tâches. **Ne jamais retenter ce 500** ; le traiter comme « recherche non supportée ». Seules les erreurs réseau et les 5xx sans ce message se retentent, une seule fois.
- `/api/hosts` pèse environ 214 champs par hôte et n'a pas de sélection de champs : `thin=true` ne renvoie que id et name. Ne garder en mémoire que les champs utiles.
- Le « statut global » de Foreman est trompeur (« Error » pour un hôte dont le détail dit seulement « Build: Installed ») : ne pas l'utiliser. Lire les statuts d'errata, de traces et de build.
- Un hôte a le plus souvent **plusieurs CV** (15 hôtes sur 19 sur l'instance de validation). Le retard de CV se calcule par couple (CV, environnement) et prend le pire. L'outil ne devine jamais quelle est la « CV de base » : c'est la configuration (`[cv:NOM]`) qui le dit.
- `errata_counts.*` = **installables** ; `errata_counts.applicable.*` = **applicables**. Seul l'installable sert aux statuts de VM.
- Sévérité d'erratum : la valeur littérale `"None"` est traitée comme absente (UNKNOWN), jamais déduite.
- `/pulp/api/v3/status/` est hors API Foreman et Katello, lisible sans authentification, `storage.*` en octets. Il ne couvre pas PostgreSQL.
- Aucune date de profil de paquets (V4) ni de début de build (V14) n'est exposée : ces indicateurs sont UNKNOWN en v1.

## Conventions de travail

- Une branche et une pull request par étape : (1) squelette, client API, config, codes retour ; (2) `summary` et `list` ; (3) `content` et `host` ; (4) README, SECURITY.md, mode monitoring documenté.
- Commits courts, au présent, un sujet par commit.
- Chaque règle de statut du cadrage a au moins un test, y compris les cas limites : champ absent, null, liste vide, seuil exactement atteint. Tests sur des réponses JSON enregistrées (`tests/fixtures/`), jamais sur une instance réelle.
- Avant de proposer un commit : `pytest`, `ruff check`, `mypy`. Tests sur Python 3.9 jusqu'à la dernière version stable en CI.
- Ne rien ajouter qui ne soit pas dans le cadrage sans le signaler. En cas de doute sur un comportement de l'API, ne pas supposer : le noter comme point à vérifier.
- Réponses et documentation en français, code, noms de variables et messages techniques d'erreur selon le cadrage.
