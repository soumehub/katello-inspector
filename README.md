# katello-inspector

Outil open source, en lecture seule, qui donne a un administrateur Katello une
vue rapide de l'etat de ses VMs, de leur retard de contenu et de la sante de
la plateforme.

Projet communautaire, non affilie aux projets Katello, Foreman ou Red Hat.

En developpement : seuls le squelette de l'outil, le client API (GET
uniquement), la configuration et les codes retour sont disponibles pour
l'instant. Voir `docs/cadrage.md` pour le perimetre complet et `CLAUDE.md`
pour les regles de contribution.

## Installation (developpement)

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## Utilisation

```sh
katello-inspector version --url https://katello.example.com --token-file /etc/katello-inspector/token
```

Le jeton se lit dans un fichier (`--token-file` ou `[auth] token_file` dans la
configuration) ou dans la variable d'environnement
`KATELLO_INSPECTOR_TOKEN` ; jamais en argument de ligne de commande.

Licence Apache 2.0.
