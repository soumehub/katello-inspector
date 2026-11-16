# Fixtures de test

Les tests de katello-inspector tournent sur des réponses JSON enregistrées, jamais sur une instance réelle. Elles viennent de l'outil de découverte temporaire (`katello_api_discovery.py`), qui écrit chaque réponse dans `raw/NNN_<tag>.json` avec la forme :

```json
{"request": {"method": "GET", "path": "...", "params": {}}, "status": 200, "kind": "ok", "elapsed_ms": 150, "response": { ... }}
```

Le champ `response` est le corps renvoyé par l'API. Le mode `--fixtures RÉPERTOIRE` de l'outil doit lire ce format, ou le répertoire contenir directement le corps, au choix à trancher au début du développement (la forme avec enveloppe permet de rejouer aussi le statut HTTP, utile pour le cas du 500).

## À conserver (par ordre d'utilité)

| Fixture | Usage |
| --- | --- |
| `/api/hosts` (liste, 19 hôtes) | summary, list, content, tous les cas de statut |
| `/api/hosts/:id` (4 fiches) | host |
| `/api/hosts/:id/errata` | host, sévérités |
| `/api/hosts/:id/traces` | host (réponses vides) |
| `/katello/api/content_views`, `/content_view_versions`, `/environments` | retard de CV, ordre de promotion |
| `/katello/api/repositories`, `/products`, `/sync_plans` | content |
| `/foreman_tasks/api/tasks` (page de 100 et recherches) | tâches en erreur, libellés |
| `/katello/api/ping`, `/api/status`, `/katello/api/status` | plateforme |
| `/pulp/api/v3/status/` | disque Pulp |
| Requête de contrôle `search=champ_inexistant…` (HTTP 500) | test « ne pas retenter ce 500 » |
| Requête `subscription_status` (HTTP 500) | idem, message « not recognized » |

## Cas à fabriquer à partir des fixtures réelles
Ils n'existent pas sur l'instance et doivent être créés en modifiant des copies :
- un hôte sans données de contenu (champs null) ;
- un hôte avec une trace en attente (`traces_status` différent de 0) ;
- un hôte en build (`build: true`) ;
- un hôte avec check-in ancien, et un hôte sans check-in ;
- un erratum de sévérité absente, et un de sévérité `"None"` ;
- une CV rolling et une CV composite ;
- une version de CV publiée mais non promue (attente de promotion) ;
- une liste vide, et une liste à plus d'une page (pagination).

## Anonymisation avant publication
L'option `--redact` de l'outil de découverte est une aide, pas une garantie. Elle masque les noms d'hôtes, les IP, les MAC et les adresses e-mail, mais pas les noms d'organisation, de CV, de produits, de dépôts, de groupes d'hôtes, de clés d'activation ni les descriptions libres des versions. Avant de pousser sur un dépôt public :
- relire les fichiers (recherche des noms d'entreprise, de domaines internes, d'utilisateurs, de jetons) ;
- remplacer les noms par des noms génériques (`cv-os-base`, `Production`, `vm01.example.com`) ;
- supprimer les champs inutiles aux tests (faits système détaillés, paramètres de l'hôte, `all_parameters`, `facts`), qui alourdissent le dépôt et peuvent contenir des secrets ;
- garder les fixtures brutes hors dépôt, ou dans un dépôt privé.
