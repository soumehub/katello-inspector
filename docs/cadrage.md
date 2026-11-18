# katello-inspector — Document de cadrage

Dernière mise à jour : 16 novembre 2026

## Contexte et objectifs

katello-inspector donne à un administrateur Katello, en lecture seule, une vue rapide de l'état de ses VMs, de leur retard de contenu et de la santé de la plateforme.

Objectifs :

- Répondre en un écran à la question « y a-t-il un problème ? », puis permettre de creuser.
- Dire clairement si une VM est réellement à jour, en distinguant ses mises à jour en attente, le retard de son environnement et la fraîcheur des données.
- Servir deux usages avec un seul moteur : l'usage manuel (sortie lisible) et le monitoring (JSON et codes retour Nagios).
- Être publiable en open source : aucune valeur propre à un environnement, aucune dépendance externe.

Principes directeurs :

- Lecture seule stricte : l'outil ne modifie jamais rien dans Katello.
- Entonnoir : du compteur global vers la liste, puis vers le détail d'une VM.
- Une information absente n'est jamais présentée comme un état sain : elle apparaît en UNKNOWN, ou en N/A si l'indicateur ne s'applique pas.
- Dégradation propre : un champ absent donne le statut UNKNOWN, jamais un plantage.
- Sobriété : sortie réduite par défaut, détail à la demande, aucune fonction ajoutée sans justification.

## Décisions figées

Le périmètre de la v1 est arrêté sur les choix ci-dessous ; toute modification passe par une mise à jour de ce document.

| Sujet | Décision |
| --- | --- |
| Nom | katello-inspector (disponibilité sur GitHub, GitLab et PyPI à confirmer avant publication) |
| Langage | Python 3.9 ou plus, bibliothèque standard uniquement |
| Source des données | API REST de Foreman et de Katello uniquement, requêtes GET uniquement |
| Interface | Outil unique avec quatre sous-commandes : summary, list, content, host |
| Versions testées | Katello 4.21, Foreman 3.19 (champs API vérifiés sur une instance réelle avec un compte Viewer, voir la liste des points vérifiés) |
| Capsules | Hors périmètre v1 ; le champ « content source » est lu et conservé dans le modèle interne |
| Conformité par Lifecycle Environment | Option `--by-lce` de `summary`, sans nouvelle sous-commande ni appel API supplémentaire |
| Statuts | OK, WARN, CRIT, UNKNOWN (information indisponible) et N/A (indicateur non applicable) |
| Configuration | Fichier INI (configparser) ; le TOML est réservé à pyproject.toml |
| Modes | Manuel (défaut) et monitoring |
| Licence | Apache 2.0 |
| Distribution | Dépôt avec pyproject.toml ; RPM dans un second temps |

Le README devra préciser que l'outil est communautaire et non affilié aux projets Katello, Foreman ou Red Hat, et indiquer la limite connue sur les capsules : une capsule peut masquer un retard de synchronisation.

## Sous-commandes et options

L'outil expose quatre sous-commandes, de la plus synthétique à la plus détaillée, plus `version`. Chacune ne fait que lire l'API.

| Sous-commande | Rôle | Contenu |
| --- | --- | --- |
| `summary` | Santé globale, un écran | Compteurs plateforme (ping, tâches en erreur, disque Pulp) et compteurs parc : total, VMs par état de mise à jour, données obsolètes, errata security installables, reboot requis, environnements en retard de CV, VMs en build. Avec `--by-lce` : synthèse de conformité par Lifecycle Environment |
| `list` | Tableau des VMs | Nom, LCE, CV et version déployée (une VM peut avoir plusieurs CV), dernier check-in, errata security installables, reboot, état de mise à jour, statut. En mode texte, une VM multi-CV n'affiche dans sa colonne CV que celle dont l'attente de promotion est la plus longue (`+N` pour les autres) ; le JSON liste toutes les CV. |
| `content` | Cohérence du contenu | Par produit et repo : dernière sync et résultat ; par CV : dernière version publiée, version déployée par LCE et durée d'attente de la plus récente, contenu synchronisé non publié ; nombre de VMs par version |
| `host NOM` | Détail d'une VM | Identité, fraîcheur des données, activation key, repos activés, errata disponibles, applicables et installables détaillés, paquets upgradables, traces, derniers jobs |
| `version` | Version de l'outil | Version d'inspector et version de Foreman et de Katello, lues via l'API |

### Options globales

| Option | Effet |
| --- | --- |
| `--config FICHIER` | Fichier INI à utiliser (voir la section Configuration) |
| `--url URL` | Adresse du serveur Katello |
| `--org NOM` | Organisation à interroger |
| `--token-file FICHIER` | Fichier contenant le token (jamais le token en argument) |
| `--ca-file FICHIER` | Bundle de CA pour valider le certificat du serveur |
| `--insecure` | Désactive la validation TLS, explicite, jamais par défaut |
| `--format text\|json` | Format de sortie (text par défaut) |
| `--monitoring` | Raccourci : sortie JSON et codes retour 0, 1, 2, 3 |
| `--no-color` | Désactive les couleurs (aussi respecté : variable `NO_COLOR`) |
| `--timeout SECONDES` | Délai maximal par appel API |
| `--capsule NOM` | Réservé pour une version ultérieure, sans effet en v1 |

### Options propres à `list`

| Option | Effet |
| --- | --- |
| `--lce NOM`, `--cv NOM`, `--hostgroup NOM` | Filtres sur l'environnement, la vue de contenu et le groupe d'hôtes. `--hostgroup` prend le **nom** du groupe (champ `hostgroup`), jamais son chemin complet : `hostgroup_fullname` et `hostgroup_title` n'ont trouvé aucun hôte avec le nom seul lors de la vérification. |
| `--problems-only` | N'affiche que les VMs dont le statut n'est pas OK |
| `--search EXPR` | Expression de recherche Foreman transmise telle quelle |
| `--sort COLONNE` | Tri (nom, check-in, errata) |
| `--limit N` | Nombre maximal de lignes |

Sans `--limit`, `list` affiche 50 lignes en mode manuel et indique combien de lignes ont été omises ; le mode monitoring renvoie toutes les lignes sélectionnées.

### Option propre à `content`

`--stale-only` n'affiche que les produits, repos ou vues de contenu en retard.

### Option propre à `summary`

`--by-lce` ajoute la synthèse de conformité par Lifecycle Environment. Elle réutilise les données déjà collectées pour le résumé et n'ajoute aucun appel API.

### Seuils

Chaque seuil se règle par option (`--checkin-days`, `--security-warn`, `--security-crit`), par variable d'environnement ou dans le fichier INI. Les valeurs par défaut sont dans la section sur les règles de statut. L'option globale --fixtures RÉPERTOIRE lit des réponses enregistrées au lieu d'appeler l'API (voir la section sur la collecte des données).

Les seuils de retard de contenu peuvent être définis par Lifecycle Environment dans le fichier INI (sections `[lce:NOM]`), car un environnement de production est souvent promu moins vite qu'un environnement de développement. Ils peuvent aussi l'être par Content View (sections \[cv:NOM\]), car la CV de base d'un OS et une CV applicative n'ont pas le même rythme de promotion.

## Configuration et authentification

Chaque paramètre se règle de quatre manières, la première trouvée l'emporte : option en ligne de commande, variable d'environnement `KATELLO_INSPECTOR_*`, fichier INI, valeur par défaut.

### Fichier INI

Recherché dans l'ordre : `--config`, la variable `KATELLO_INSPECTOR_CONFIG`, `~/.config/katello-inspector/config.ini`, `/etc/katello-inspector/config.ini`.

```ini
[server]
url = https://katello.example.com
organization = MonOrganisation
ca_file = /etc/pki/tls/certs/ca-interne.pem
timeout = 30
page_size = 200

[auth]
user = inspector-ro
token_file = /etc/katello-inspector/token

[thresholds]
checkin_days = 7
# profile_days = 30   (sans effet : aucune date de profil exposée, V4)
security_warn = 1
security_crit = 10
stale_publish_days = 14
cv_lag_warn_days = 14
cv_lag_crit_days = 45
# build_stuck_hours = 24   (sans effet : début de build non exposé, V14)
disk_warn_pct = 20
disk_crit_pct = 10

[lce:Production]
cv_lag_warn_days = 30
cv_lag_crit_days = 90

[lce:Development]
cv_lag_check = false

[cv:cv-app-tomcat]
cv_lag_warn_days = 45
cv_lag_crit_days = 120

[output]
color = auto
```

Les valeurs sont des points de départ sans valeur normative, à ajuster selon la politique de promotion de chaque équipe. Une section `[lce:NOM]` surcharge les seuils de retard pour cet environnement seulement ; `cv_lag_check = false` désactive le contrôle du retard de CV pour lui, et l'indicateur passe alors en N/A. Une section \[cv:NOM\] fait de même pour une Content View, dans tous les environnements, et l'emporte sur la section de l'environnement : l'ordre de priorité est \[cv:NOM\], puis \[lce:NOM\], puis \[thresholds\]. Le seuil `profile_days` est sans effet en v1, car l'API n'expose aucune date de profil de paquets (V4) ; il en va de même pour build\_stuck\_hours (V14), faute de date de début de build. Les deux sont commentés dans l'exemple.

### Authentification

- Compte dédié en lecture seule, avec le rôle Viewer, à recommander dans le README ; la validation a été faite avec ce rôle, sans aucun refus 403 sur les endpoints utilisés (V15).
- Jeton d'accès personnel Foreman, transmis en authentification HTTP Basic avec le nom du compte.
- Le jeton se lit dans un fichier (`token_file`) ou, à défaut, dans `KATELLO_INSPECTOR_TOKEN`. Jamais en argument de ligne de commande, car il serait visible dans `ps`.
- Si le fichier du jeton est lisible par le groupe ou par tous, l'outil affiche un avertissement ; il refuse de démarrer en mode `--monitoring` avec un fichier de jeton accessible en écriture par d'autres.
- Le jeton n'apparaît jamais dans les logs, les messages d'erreur ni la sortie JSON.

### TLS

Le certificat du serveur est validé par défaut avec les CA du système, ou avec `ca_file`. `--insecure` doit être passé explicitement à chaque appel, et l'outil l'indique dans sa sortie.

`--url` doit être en `https://` ; une adresse en `http://` est refusée sans aucune option pour l'autoriser, car le jeton y circulerait en clair (authentification HTTP Basic). Aucune redirection HTTP n'est suivie, quelle que soit sa cible : urllib reconduit l'en-tête `Authorization` sur une redirection par défaut, y compris vers une autre origine ou vers `http://`, donc la seule politique sûre est de n'en suivre aucune.

## Règles de statut

Chaque indicateur reçoit l'un des cinq statuts OK, WARN, CRIT, UNKNOWN ou N/A ; les règles d'agrégation sont données en fin de section. Tous les seuils sont configurables ; les valeurs ci-dessous sont les défauts.

### Errata : disponibles, applicables, installables

Ces trois notions sont distinctes, et seul le nombre d'errata installables dit ce qu'on peut appliquer maintenant à une VM. Elles ont été vérifiées sur une instance 4.21 (point V3) : la liste des hôtes fournit les compteurs installables (errata\_counts) et applicables (errata\_counts.applicable), comparés à l'interface sur une VM pour les errata security (1 installable, 20 applicables). Le type bugfix a aussi été comparé (1 installable, 1 applicable) ; enhancement n'a pas pu l'être, aucun erratum de ce type n'étant en attente.

| Notion | Définition | Portée | Usage dans l'outil |
| --- | --- | --- | --- |
| Disponible | Erratum présent dans les dépôts synchronisés ou dans une version de CV, indépendamment de toute VM | Contenu | Information dans `content`, jamais un statut de VM |
| Applicable | Erratum qui concerne un paquet installé sur la VM, d'après son profil de paquets | VM | Compteur affiché dans `host` |
| Installable | Erratum applicable et présent dans le contenu réellement accessible à la VM (sa CV dans son Lifecycle Environment) | VM | Seul compteur utilisé pour les statuts de VM |
| Applicable non installable | Erratum applicable, mais présent seulement dans du contenu que la VM ne voit pas encore (version publiée non promue, ou contenu synchronisé non publié) | VM | Signalé comme « contenu en attente », sans changer le statut par lui-même |

Conséquence : une VM sans erratum installable n'est pas forcément à jour. Si son environnement a du retard, des correctifs applicables lui sont invisibles. Un compteur à zéro n'est donc jamais présenté seul comme « à jour ».

### État de mise à jour d'une VM

L'état de mise à jour est une étiquette de lecture ; le statut OK, WARN ou CRIT reste calculé par les indicateurs plus bas. Les conditions sont testées dans l'ordre du tableau.

| Valeur JSON | Affichage dans `list` | Condition |
| --- | --- | --- |
| `unverifiable` | ? | Le check-in n'est pas OK (la fraîcheur du profil de paquets n'est pas exposée, V4, et n'entre pas dans ce calcul), ou les compteurs d'errata sont UNKNOWN : les compteurs ne permettent pas de conclure |
| `outdated` | Non | Au moins un erratum installable, tous types confondus |
| `up_to_date_content_pending` | Oui\* | Aucun erratum installable, mais des errata applicables non installables, ou une version plus récente de la CV attend d'être promue dans l'environnement |
| `up_to_date` | Oui | Données fraîches, aucun erratum installable, aucun contenu en attente |
| `n/a` | — | VM sans données de contenu Katello (hôte seulement géré par Foreman) |

### Retard de Content View

Une version plus récente, synchronisée ou publiée, ne doit pas forcément être déployée tout de suite : chaque équipe promeut à son rythme, et la production est volontairement en retard sur le développement. L'outil mesure donc trois choses distinctes, avec des sévérités différentes.

| Notion | Définition | Mesure | Sévérité par défaut |
| --- | --- | --- | --- |
| Contenu synchronisé non publié | Un dépôt a été synchronisé après la dernière publication de la CV (points V7, V8). La comparaison porte sur deux dates, car l'API n'indique pas si la synchronisation a changé du contenu : une synchronisation sans nouveauté peut donc être signalée | Jours depuis cette synchronisation | WARN au-delà de `stale_publish_days`, jamais CRIT, car publier est une décision |
| Version publiée non promue | Une version de CV plus récente que celle déployée dans un environnement existe | Jours d'attente depuis la publication de la première version plus récente non déployée | WARN au-delà de `cv_lag_warn_days`, CRIT au-delà de `cv_lag_crit_days`, par environnement |
| Version déployée | Version de la CV réellement servie aux VMs d'un environnement | Numéro de version | Information, jamais un statut |

Dans ce document, « retard de CV » désigne uniquement la deuxième ligne. Il se mesure en durée d'attente, pas en nombre de versions, et se compare à une tolérance propre à chaque environnement. Une VM dont l'environnement est en retard mais dans la tolérance reste « Oui\* » : elle est à jour pour ce qui lui est proposé, et l'outil indique ce qui attend.

Une VM n'a pas sa propre version de CV : elle reçoit celle qui est déployée dans son environnement. Le retard concerne donc le couple CV et environnement, pas la VM seule. Ce modèle est confirmé sur Katello 4.21 (point V6) : un hôte a une ou plusieurs CV, chacune dans un environnement, et la liste des hôtes donne la version servie pour chaque couple, comparée à l'interface sur un hôte à deux CV. Une VM est donc rattachée à une liste de couples (CV, environnement, version) et son indicateur de retard de CV prend le pire des couples. Chaque CV peut avoir ses propres seuils (sections \[cv:NOM\]), ce qui permet de traiter la CV de base de l'OS plus strictement que les CV applicatives ; l'outil ne devine jamais quelle CV est la CV de base, c'est la configuration qui le dit.

### Indicateurs par VM

| Indicateur | WARN | CRIT | N/A quand | UNKNOWN quand |
| --- | --- | --- | --- | --- |
| Dernier check-in (V1) | — | plus ancien que `checkin_days` | VM sans données de contenu | date absente ou null |
| Profil de paquets (V4) | plus ancien que `profile_days` | — | VM sans données de contenu | toujours en v1 : aucune date exposée par l'API (V4) |
| Errata security installables (V3) | au moins `security_warn` | au moins `security_crit` | VM sans données de contenu, ou en build | compteurs absents |
| Retard de CV de l'environnement | attente d'au moins `cv_lag_warn_days` | attente d'au moins `cv_lag_crit_days` | environnement ou CV avec `cv_lag_check = false`, CV rolling | date de publication absente |
| Traces : reboot ou service à redémarrer (V13) | au moins 1 trace | — | VM sans données de contenu, ou en build | endpoint ou champ indisponible |
| Build (V14) | en build depuis plus de `build_stuck_hours` | — | VM hors build | toujours en v1 (V14) : durée non exposée, la VM est seulement signalée « en build », sans statut |

Aucune date de profil de paquets n'est exposée (V4) : les compteurs d'errata ne sont donc datés que par le check-in, et l'outil le dit dans sa sortie. Le statut global de Foreman n'est pas utilisé, car il agrège des sous-statuts de façon peu lisible (un hôte à l'état « Error » alors que le détail affiché ne mentionne que « Build: Installed ») : l'outil lit directement les statuts d'errata, de traces et de build.

### Indicateurs de contenu

| Indicateur | WARN | CRIT | N/A quand | UNKNOWN quand |
| --- | --- | --- | --- | --- |
| Dernière synchronisation d'un repo (V8) | — | dernier résultat en échec, ou jamais synchronisé | repo sans source distante (contenu téléversé) | date ou résultat absent |
| Contenu synchronisé non publié (V7) | attente au-delà de `stale_publish_days` | — | CV rolling | date de publication absente |
| Version publiée non promue, par CV et environnement | d'au moins `cv_lag_warn_days` | d'au moins `cv_lag_crit_days` | environnement ou CV dispensé, CV rolling | dates absentes |
| CV composite : composant plus récent (V7) | attente au-delà de `stale_publish_days` | — | CV non composite | liste des composants absente |

### Indicateurs de plateforme

| Indicateur | WARN | CRIT | UNKNOWN quand |
| --- | --- | --- | --- |
| Ping des services (V10) | — | au moins un service en échec | endpoint inaccessible avec le rôle Viewer |
| Tâches en erreur ou en pause sur 24 h (V9) | au moins 1 | une tâche de sync, publication ou promotion | recherche par état non supportée |
| Espace disque Pulp (V11) | moins de `disk_warn_pct` libre | moins de `disk_crit_pct` libre | endpoint Pulp absent ou inaccessible (lu hors API Foreman, V11) |

L'espace disque de Pulp vient de `/pulp/api/v3/status/`, hors API Foreman et Katello : ses valeurs storage.total, used et free correspondent à `df` sur /var/lib/pulp, et ne couvrent ni /var/lib/pgsql ni les autres filesystems. Côté tâches, la recherche par état, résultat et date fonctionne ; les libellés de synchronisation (Actions::Katello::Repository::Sync et Actions::Katello::SyncPlan::Run) sont observés, ceux de publication et de promotion restent à relever.

### Règles d'agrégation

1. **N/A** : l'indicateur ne s'applique pas à cet élément. Il est ignoré dans tous les calculs, affiché « — » et absent de la liste `unknown`.
2. **UNKNOWN** : l'indicateur s'applique, mais sa valeur n'a pas pu être établie (champ absent, valeur null, droit insuffisant, version non testée). Il est compté, affiché « ? » et listé avec sa raison.
3. **Ordre de gravité** d'un élément (VM, CV, environnement, plateforme) : CRIT, puis WARN, puis UNKNOWN, puis OK. Un UNKNOWN ne masque jamais un WARN ou un CRIT, et ne rend jamais un élément OK.
4. Un élément dont tous les indicateurs sont N/A est lui-même N/A et exclu des agrégats parents ; `summary` compte ces éléments à part.
5. Le statut d'une commande est le pire statut des éléments évalués. Si aucun élément n'a pu être évalué (liste vide, tout en N/A), le statut est UNKNOWN : une supervision ne doit pas annoncer un état sain quand rien n'a été examiné.
6. Les colonnes d'information (errata hors security, applicables non installables, version déployée) n'entrent dans aucun statut.
7. Le profil de paquets (V4) et la durée de build (V14) sont structurellement indisponibles en v1 : affichés avec leur raison (« ? » ou « en build »), comptés une seule fois dans `unknown` au niveau de la commande (jamais répétés par VM), mais **exclus** du calcul du statut d'une VM. Seuls le check-in, les errata security installables, le retard de CV et les traces entrent dans ce calcul.

### Synthèse de conformité par Lifecycle Environment

Elle est ajoutée comme option `--by-lce` de `summary`, pas comme sous-commande : elle répond à la question « quel environnement est en défaut ? », réutilise les données déjà collectées et n'ajoute aucun appel API.

| Colonne | Contenu |
| --- | --- |
| LCE | Nom, classé selon le chemin de promotion si l'API le permet (V7), sinon par ordre alphabétique |
| VMs | Nombre de VMs évaluées, hors N/A |
| Statuts | Nombre de VMs OK, WARN, CRIT et UNKNOWN |
| À jour | Nombre de VMs Oui, Oui\*, Non et ? |
| Errata security installables | Somme sur les VMs ; un même erratum compte une fois par VM (V3) |
| Dont critiques | Errata security de sévérité critique ; « ? » si la sévérité est absente des métadonnées, jamais déduite ; la valeur « None » est traitée comme absente (V5) |
| Données obsolètes | VMs dont le check-in ou le profil de paquets dépasse son seuil |
| Attente de CV | Plus longue attente d'une version non promue dans cet environnement, en jours |
| Statut | Pire statut des VMs de l'environnement |

Une VM est rattachée à chaque LCE où elle a au moins un couple (CV, environnement) : dans le cas normal elle n'en a qu'un. Si elle en avait plusieurs (cas non observé, non exclu par l'API), elle compterait dans chacune des lignes correspondantes : la somme des VMs sur toutes les lignes peut alors dépasser le total du parc. `Dont critiques` reste toujours `?` en v1 : la sévérité par erratum vient de l'endpoint par hôte, hors de `summary` (pas d'appel par VM).

Exemple illustratif de sortie en mode manuel :

```text
LCE          VMs   OK  WARN  CRIT  ?   A jour (Oui/Oui*/Non/?)  Sec.inst.  Critiques  Obsoletes  Attente CV  Statut
Development   12   10     2     0  0   9/2/1/0                  3          ?          0          0 j         WARN
Production    48   40     6     2  0   30/10/6/2                21         ?          2          19 j        CRIT
```

## Sortie JSON, mode monitoring et codes retour

Le format JSON est un contrat stable : il peut gagner des champs, mais un champ existant ne change ni de nom ni de sens sans incrémenter `schema_version`.

### Enveloppe commune

Toutes les sous-commandes renvoient la même enveloppe ; seul le contenu de `data` change.

```json
{
  "schema_version": "1",
  "tool": { "name": "katello-inspector", "version": "0.1.0" },
  "generated_at": "2026-11-16T11:30:00Z",
  "command": "list",
  "server": {
    "url": "https://katello.example.com",
    "organization": "MonOrganisation",
    "katello_version": "4.21.1.1",
    "foreman_version": "3.19.0"
  },
  "status": "WARN",
  "thresholds": { "checkin_days": 7, "security_warn": 1, "security_crit": 10 },
  "data": {},
  "unknown": [
    { "indicator": "pulp_disk", "reason": "champ non exposé par l'API" }
  ]
}
```

Si l'outil lui-même échoue (erreur de configuration, d'API ou inattendue, en mode `--monitoring`), l'enveloppe renvoyée a les mêmes clés que ci-dessus : `command` (ou `null` si l'échec a eu lieu avant de savoir laquelle), `server` (ce qui en est connu, `null` sinon), `status` à `"UNKNOWN"`, `data` à `{}`, `unknown` avec une entrée `"indicator": "tool"`, plus un champ supplémentaire `"error"` (la même chaîne, au premier niveau, pour un consommateur qui veut l'erreur sans aller chercher dans `unknown`). Aucun champ n'est donc absent ou remplacé par une forme différente simplement parce que la commande a échoué.

### Contenu de `data` pour `list` (une entrée par VM)

```json
{
  "name": "vm01.example.com",
  "status": "WARN",
  "update_state": "up_to_date_content_pending",
  "lifecycle_environment": "Production",
  "content_views": [ { "name": "cv-rocky9", "version_deployed": "12.0", "latest_published": "13.0", "waiting_days": 9 } ],
  "freshness": { "last_checkin": "2026-11-15T22:10:00Z", "checkin_age_days": 0, "package_profile_age_days": null },
  "errata": {
    "installable": { "security": 0, "bugfix": 0, "enhancement": 0 },
    "applicable_not_installable": { "security": 3 }
  },
  "reboot_required": true,
  "content_source": "katello.example.com",
  "indicators": { "checkin": "OK", "profile": "UNKNOWN", "errata_security": "OK", "cv_lag": "OK", "traces": "WARN", "build": "N/A" }
}
```

Un champ dont la source API n'est pas confirmée (points V) vaut `null` et son indicateur passe en UNKNOWN ; il n'est jamais remplacé par une valeur par défaut. Le champ `content_source` est rempli dès la v1 pour que la prise en charge des capsules n'oblige pas à changer le schéma. La date du profil de paquets est null, car l'API n'expose aucune date (V4).

### Contenu de `data` pour `summary`

```json
{
  "platform": {
    "ping": { "status": "OK", "services": { "candlepin": "ok", "pulp3": "ok", "pulp3_content": "ok" } },
    "tasks": {
      "status": "CRIT",
      "failing_or_paused_24h": 3,
      "tasks": [
        { "label": "Actions::Katello::Repository::Sync", "state": "stopped", "result": "error", "started_at": "2026-11-16T01:00:19Z" }
      ],
      "tasks_omitted": 0
    },
    "pulp_disk": { "status": "OK", "free_pct": 64.02, "total_bytes": 321965260800, "used_bytes": 115839705088, "free_bytes": 206125555712 }
  },
  "fleet": {
    "total": 19,
    "evaluated": 18,
    "na": 1,
    "status_counts": { "OK": 10, "WARN": 5, "CRIT": 2, "UNKNOWN": 1 },
    "update_state_counts": { "up_to_date": 8, "up_to_date_content_pending": 4, "outdated": 5, "unverifiable": 1, "n/a": 1 },
    "stale_data": 1,
    "security_installable_total": 14,
    "reboot_required": 2,
    "in_build": 1,
    "cv_lag_environments": 1
  },
  "by_lce": null
}
```

`platform.tasks.status` : CRIT si au moins une des tâches en erreur ou en pause des dernières 24h porte un libellé `Actions::Katello::Repository::Sync`, `Actions::Katello::ContentView::Publish`, `Actions::Katello::ContentView::Promote` ou `Actions::Katello::SyncPlan::Run` ; sinon WARN si `failing_or_paused_24h > 0` ; sinon OK. `failing_or_paused_24h` est le total renvoyé par l'API (`subtotal`), pas le nombre d'éléments listés : `tasks` est plafonné à 50 lignes, `tasks_omitted` donne le nombre de lignes au-delà de ce plafond. `platform.pulp_disk` est lu sans authentification (voir plus haut).

`fleet.security_installable_total` et `fleet.reboot_required` excluent les VMs N/A et en build (ces indicateurs y sont eux-mêmes N/A). `fleet.cv_lag_environments` est le nombre de Lifecycle Environments distincts ayant au moins un couple (CV, environnement) en WARN ou CRIT. `by_lce` vaut `null` sans `--by-lce` ; avec l'option, c'est la liste décrite ci-dessous.

### Contenu de `data.by_lce` pour `summary --by-lce`

```json
{
  "name": "Production",
  "vms": 48,
  "status_counts": { "OK": 40, "WARN": 6, "CRIT": 2, "UNKNOWN": 0 },
  "update_state_counts": { "up_to_date": 30, "up_to_date_content_pending": 10, "outdated": 6, "unverifiable": 2, "n/a": 0 },
  "security_installable_total": 21,
  "security_critical_total": null,
  "stale_data_vms": 2,
  "in_build": 1,
  "max_cv_waiting_days": 19,
  "status": "CRIT"
}
```

### Modes de sortie et codes retour

|  | Mode manuel (défaut) | Mode `--monitoring` |
| --- | --- | --- |
| Format | Texte lisible, coloré si le terminal le permet | JSON compact sur la sortie standard, rien d'autre |
| Messages et logs | Sortie standard et erreur standard | Erreur standard uniquement |
| Code 0 | Commande exécutée, quel que soit l'état constaté | OK |
| Code 1 | Erreur d'exécution (réseau, authentification, exception inattendue) | WARNING |
| Code 2 | Erreur d'usage (option inconnue, configuration invalide) | CRITICAL |
| Code 3 | Non utilisé | UNKNOWN, y compris toute erreur d'exécution ou d'usage de l'outil |

En mode manuel, le code retour décrit seulement le déroulement de la commande. En mode monitoring, il décrit l'état constaté selon la convention Nagios (0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN), et toute défaillance de l'outil lui-même donne 3, jamais 1 ou 2.

Deux pièges sont traités explicitement. L'analyse des arguments de Python renvoie 2 par défaut sur une erreur d'usage, ce qu'une supervision lirait comme CRITICAL, et une exception non interceptée renvoie 1, lu comme WARNING. En mode monitoring, un gestionnaire d'erreurs central convertit les deux en code 3, avec un JSON dont `status` vaut UNKNOWN.

Les codes 0 à 3 conviennent à Nagios, Icinga et Checkmk. Zabbix s'appuie sur la sortie standard et non sur ces codes : on y consomme le JSON, avec des éléments dépendants et des expressions JSONPath sur `status` et sur les compteurs de `summary`. L'option `--format json` seule fournit ce JSON avec un code 0 en cas de déroulement normal. En cas d'échec, elle est respectée aussi : l'enveloppe ci-dessus part sur la sortie standard au lieu d'une ligne de texte sur la sortie d'erreur, mais le code retour reste celui du mode manuel (1 ou 2), pas celui de `--monitoring`. Selon la version de Zabbix et le mode de collecte, un code non nul peut rendre l'élément non supporté, ce qui est à valider. Une ligne de texte au format des plugins Nagios, avec données de performance, n'est pas prévue en v1 ; elle serait ajoutée si des utilisateurs de Nagios la demandent.

## Collecte des données et dégradation

L'outil n'utilise que l'API REST de Foreman et de Katello, jamais hammer ni la base de données. Les endpoints et champs ci-dessous ont été examinés le 16 novembre 2026 sur une instance Katello 4.21 / Foreman 3.19, avec un compte Viewer, au moyen d'un outil de découverte temporaire qui n'émet que des requêtes GET. Chaque ligne renvoie à un point V dont le résultat figure dans la liste en fin de document. Qu'un champ existe ne prouve pas son sens : seules les correspondances comparées à l'interface sont tenues pour validées, les autres sont signalées comme telles.

| Donnée | Source API | Utilisée par | Point à vérifier |
| --- | --- | --- | --- |
| Version de Foreman et de Katello | `/api/status`, `/katello/api/status` | toutes (en-tête) | V10 |
| Santé des services | `/katello/api/ping` | `summary` | V10 |
| Liste des hôtes avec CV, environnement, errata installables et applicables, paquets upgradables, check-in, content source | `/api/hosts` | `summary`, `list`, `content` | V1, V3 |
| Date du dernier profil de paquets | aucun champ exposé | `summary`, `list`, `host` | V4 |
| Statuts de l'hôte (errata, traces, build) | `/api/hosts` | `list`, `host` | V14 |
| Traces : statut dans la liste des hôtes, détail par hôte | `/api/hosts/:id/traces` | `summary`, `list` (statut), `host` (détail) | V13 |
| Errata d'un hôte, avec sévérité | `/api/hosts/:id/errata` | `host` | V3, V5 |
| Produits et plans de sync | `/katello/api/products`, `/katello/api/sync_plans` | `content` | V8 |
| Repos, dernière sync et résultat | `/katello/api/repositories` | `content` | V8 |
| CV, versions, dates de publication, environnements | `/katello/api/content_views`, `/katello/api/content_view_versions`, `/katello/api/environments` | `content`, `list`, `summary` | V6, V7 |
| Tâches en erreur ou en pause | `/foreman_tasks/api/tasks` avec recherche sur l'état | `summary` | V9 |
| Espace disque de Pulp | /pulp/api/v3/status/ (hors API Foreman et Katello) | `summary` | V11 |

### Performances sur un grand parc

L'objectif est de gérer plusieurs centaines de VMs, et plus de 1 000, sans que la durée d'exécution ni la charge sur Katello dépendent du nombre de VMs, sauf pour la liste elle-même. Ces objectifs ne sont pas des promesses. Sur l'instance de validation (19 hôtes), une page de la liste coûte environ 47 ms par hôte, soit une extrapolation d'environ 45 s pour 1 000 hôtes, à confirmer sur un parc plus grand (V12) ; un comptage avec une page d'une ligne prend 150 à 250 ms.

- **Pagination systématique** avec une taille de page `page_size` configurable (200 par défaut) ; la réponse indique total, subtotal, page et per\_page (V12). Un plafond de per\_page n'a pas pu être observé avec 19 hôtes (500 est accepté). Aucune réponse n'est supposée tenir en une page.
- **Filtrage côté API** : les filtres (`--lce`, `--cv`, `--hostgroup`, `--search`) sont traduits en recherche Foreman envoyée au serveur, au lieu de télécharger tout le parc puis de filtrer. Les champs last\_checkin, errata\_status, trace\_status, build, lifecycle\_environment, content\_view et hostgroup sont acceptés (V2), pas subscription\_status. Un champ inconnu fait répondre 500 sur les hôtes (400 sur les tâches) : l'outil n'envoie que des champs connus et traite ce message comme une absence de support, sans nouvelle tentative.
- **Comptage sans transfert** : les compteurs de `summary` utilisent le total renvoyé par l'API avec une page d'une seule ligne, un appel par compteur, plutôt que de télécharger les VMs (V2, V12). Sans recherche utilisable, l'outil se rabat sur la liste complète paginée.
- **Champs réduits** : l'API n'offre pas de sélection de champs : thin=true ne renvoie que l'identifiant et le nom, alors qu'un hôte pèse environ 214 champs dans la liste. L'outil ne garde en mémoire que les champs nécessaires, pas les réponses brutes (V1, V12).
- **Aucun appel par VM hors de `host`** : jamais de boucle d'appels sur les VMs dans `summary`, `list` ou `content`. Les compteurs d'errata (installables et applicables), le statut des traces et la version de CV servie figurent dans la liste des hôtes (V1, V3, V6, V13) ; le nombre de VMs par version de CV s'en déduit. Si un champ n'est pas dans la liste (V1), l'indicateur correspondant est UNKNOWN et le README documente cette limite, plutôt que de multiplier les appels.
- **Appels séquentiels** dans un seul fil d'exécution, sans parallélisme en v1, pour ne pas charger Katello ; à reconsidérer seulement si une mesure l'impose.
- **Fiabilité** : délai maximal `timeout` par appel. Une seule nouvelle tentative (deux au total), limitée aux pannes transitoires : timeout, reset de connexion, et réponses HTTP 502/503/504. Jamais de nouvelle tentative sur un 4xx, sur un 5xx hors de cette liste, sur une connexion refusée, un échec DNS, une erreur TLS/certificat, ni sur la réponse 500 d'une recherche refusée (« not recognized for searching ») : ce sont des échecs déterministes, les retenter ne change rien.
- **Pas de cache en v1** : chaque exécution donne un instantané fidèle. En monitoring, la fréquence se règle côté supervision.

| Sous-commande | Appels API | Croissance avec le nombre de VMs |
| --- | --- | --- |
| `summary` | Version, ping, tâches, disque Pulp, organisation, environnements, content views, versions de CV, **plus la liste complète des hôtes** (une page par tranche de `page_size`) | Linéaire, comme `list` |
| `list` | Une page par tranche de `page_size`, plus CV et versions | Linéaire : 1 000 VMs avec 200 par page donnent 5 pages |
| `content` | Produits, repos, CV et versions paginés, plus la liste des hôtes pour compter les VMs par version | Seulement par la liste des hôtes |
| `host` | Quelques appels pour une seule VM | Aucune |

**Révision par rapport à l'estimation initiale** : `summary` ne peut pas se limiter à des comptages serveur (V2) pour ses compteurs parc (VMs par état de mise à jour, errata security installables, environnements en retard de CV, etc.), car ces états sont une classification propre à l'outil, pas un champ de recherche Foreman — il n'existe donc pas de comptage serveur qui leur corresponde directement. `summary` lit donc la liste complète des hôtes, exactement comme `list` (mais sans l'afficher ligne à ligne), et son coût croît avec le nombre de VMs. Seuls les compteurs vraiment plateforme (ping, tâches, disque Pulp) restent indépendants du parc. `--by-lce` reste gratuit : il réutilise cette même liste, sans appel supplémentaire.

### Dégradation en UNKNOWN et usage de N/A

Chaque lecture de champ passe par une fonction qui tolère l'absence et la valeur `null`. Si un champ manque, que l'API renvoie 403 faute de droit, ou que la version de Katello est hors de celles testées, l'indicateur concerné passe à UNKNOWN avec la raison dans la liste `unknown` de la sortie, et les autres indicateurs sont calculés normalement. N/A est réservé aux indicateurs qui ne s'appliquent pas, selon les règles de la section précédente : l'outil ne classe jamais en N/A une information simplement absente.

### Données de test

Un mode `--fixtures RÉPERTOIRE` lit des réponses JSON enregistrées au lieu d'appeler l'API. Il sert aux tests automatiques et aux contributeurs qui n'ont pas d'instance Katello.

## Sécurité, structure du dépôt et qualité

La lecture seule est une garantie que l'outil prouve par ses tests, pas seulement par sa documentation.

### Sécurité

- Seules des requêtes HTTP GET sont émises ; un test automatique échoue si une autre méthode apparaît dans le code.
- Aucun appel à un shell ni à un sous-processus, et aucune évaluation dynamique de code.
- Le jeton n'est jamais journalisé ni affiché, y compris en mode débogage.
- Compte dédié avec le rôle Viewer ; la documentation décrit la création de ce compte et les droits minimaux nécessaires.
- Un fichier SECURITY.md indique comment signaler une vulnérabilité.

### Structure du dépôt

Le moteur de collecte et d'analyse est séparé de l'affichage : ajouter un format de sortie ne touche pas aux règles de statut.

```text
katello-inspector/
  pyproject.toml
  LICENSE
  README.md
  CHANGELOG.md
  CONTRIBUTING.md
  SECURITY.md
  src/katello_inspector/
    cli.py          sous-commandes et options
    config.py       INI, variables d'environnement, priorités
    api.py          client HTTP, pagination, TLS, GET uniquement
    collect.py      lecture des données Katello
    analyze.py      calcul des statuts et seuils
    render_text.py  sortie lisible
    render_json.py  sortie JSON et codes retour
    commands/       summary, list, content, host
  tests/
    fixtures/       réponses JSON enregistrées
  docs/
```

### Qualité

- Tests avec pytest sur des réponses JSON enregistrées, sans instance Katello.
- Tests sur Python 3.9 jusqu'à la dernière version stable, en intégration continue, avec contrôle de style et de typage.
- Chaque règle de statut de ce document correspond à au moins un test, y compris les cas limites : champ absent, valeur null, liste vide, seuil exactement atteint.
- Tests dédiés à la distinction entre UNKNOWN et N/A, à l'ordre d'agrégation, aux cinq valeurs de l'état de mise à jour et à la tolérance de retard par environnement.
- Tests des codes retour dans les deux modes, dont l'erreur d'usage et l'exception inattendue en mode monitoring, qui doivent donner 3.
- Test de volumétrie sur un jeu synthétique de 1 000 VMs : pagination correcte et nombre d'appels qui ne croît pas avec le nombre de VMs, hors `host`.
- La v1 est terminée quand les points restant à vérifier (liste en fin de document) ont été traités sur une instance Katello 4.21 réelle, que les quatre sous-commandes fonctionnent, que le mode monitoring a été branché sur un outil de supervision, que la durée a été mesurée sur le parc réel, et que le README donne un exemple de sortie pour chaque sous-commande.

## Hors périmètre v1 et évolutions

La v1 ne traite pas les points suivants ; chacun a une place prévue dans la conception.

| Sujet | Pourquoi pas en v1 | Ce qui est déjà prévu |
| --- | --- | --- |
| Capsules | Pas de capsule disponible pour tester | Champ `content_source` dans le JSON, option `--capsule` réservée ; à ajouter : état de sync de chaque capsule et détection d'un retard côté capsule |
| Paquet RPM | La distribution par dépôt suffit pour démarrer | Structure en paquet Python compatible avec un spec RPM |
| Historique et tendances | Un instantané suffit à l'usage visé | Le JSON horodaté peut être archivé par l'utilisateur |
| Actions correctives (sync, publication, promotion) | L'outil reste en lecture seule | Aucune ; une évolution de ce type changerait la garantie de sécurité et demanderait une décision explicite |
| Katello 5.0 | Version non encore testée | Dégradation en UNKNOWN si un champ a changé ; ajout aux versions testées après validation |
| Ligne de sortie au format plugin Nagios, avec données de performance | Le JSON compact suffit pour démarrer, aucun besoin exprimé | Ajout possible comme format de sortie supplémentaire, sans toucher au moteur |
| Appels parallèles | Risque de charge sur Katello, aucun besoin mesuré | À reconsidérer après mesure (V12) |
| Appels par VM pour compléter une liste incomplète | Ferait croître la charge avec le parc | Champ absent de la liste : indicateur en UNKNOWN, limite documentée |

### Points vérifiés sur une instance Katello 4.21 et points restants

Ces points ont été vérifiés le 16 novembre 2026 sur une instance Katello 4.21 / Foreman 3.19 (19 hôtes, 9 CV, 3 environnements) avec un compte Viewer. CONFIRMÉ signifie que le champ existe et, quand c'est précisé, que sa valeur a été comparée à l'interface ; cela ne vaut pas pour d'autres versions de Katello. Chaque résultat est consigné dans le dépôt, car il définit les versions réellement testées.

| Réf. | Point | Résultat | Constat et conséquence retenue |
| --- | --- | --- | --- |
| V1 | Champs de la liste des hôtes | CONFIRMÉ | Check-in, CV, environnement, compteurs d'errata, paquets, content source et statuts sont dans la liste : aucun appel par VM. |
| V2 | Recherche sur les hôtes | CONFIRMÉ | last\_checkin, errata\_status, trace\_status, build, lifecycle\_environment et content\_view sont acceptés, pas subscription\_status. Un champ inconnu renvoie 500 (400 sur les tâches). Les comptages n'ont pas été comparés à l'interface. |
| V3 | Errata applicables et installables | CONFIRMÉ (compteurs de la liste) | errata\_counts = installables, errata\_counts.applicable = applicables, comparés à l'interface sur security (1 et 20). bugfix comparé aussi (1 installable et 1 applicable, conforme à l'interface) ; enhancement non comparé, aucun erratum de ce type n'étant en attente. Les paramètres errata\_restrict\_\* de l'endpoint par hôte n'ont rien prouvé et ne sont pas utilisés. |
| V4 | Date du profil de paquets | NON DISPONIBLE | Aucun champ explicite : indicateur toujours UNKNOWN, seul le check-in est évalué. |
| V5 | Sévérité des errata | CONFIRMÉ | Présente (Critical, Important, Moderate, Low) ; 2 errata security sur 276 valent « None » : sévérité inconnue. |
| V6 | Hôte, CV, version servie | CONFIRMÉ | Un hôte a une ou plusieurs CV (15 hôtes sur 19 en ont plusieurs) ; content\_view\_environments\[\] donne la version servie par couple, dans content\_view.content\_view\_version, \_id et \_latest. Cette version est retrouvée dans les versions du couple pour les 9 couples échantillonnés, et comparée à l'interface sur un hôte. Le retard se lit par couple. |
| V7 | Versions de CV | CONFIRMÉ (sauf composites) | created\_at = date de publication, last\_event = dernier événement (une promotion), comparés à l'interface. Chemin de promotion, composite, rolling et needs\_publish présents. Composants des CV composites non testés (aucune composite). |
| V8 | Synchronisation des dépôts | PARTIELLEMENT CONFIRMÉ | Date et résultat de la dernière sync présents ; aucun indicateur de changement de contenu (seulement des compteurs). Le contenu non publié se mesure par comparaison de dates. |
| V9 | Tâches | CONFIRMÉ | Recherche par état, résultat et date acceptée. Libellés observés : Actions::Katello::Repository::Sync, Actions::Katello::SyncPlan::Run, Actions::Katello::ContentView::Publish et Actions::Katello::ContentView::Promote. L'input d'une publication donne content\_view.id et content\_view\_version\_id ; celui d'une promotion, content\_view.id et environments\[\]. |
| V10 | Status et ping | CONFIRMÉ | Ping par service, version de Foreman (3.19.1) et version de Katello (4.21.1.1, via /katello/api/status) lisibles. Une première lecture « 0.0.0.0 » venait de l'outil de découverte, dont l'option de masquage des IP transformait cette version à quatre composantes. |
| V11 | Disque Pulp | CONFIRMÉ (filesystem Pulp) | /pulp/api/v3/status/ donne storage.total, used et free en octets, qui correspondent à df sur /var/lib/pulp ; lisible sans authentification, hors API Foreman, ne couvre pas PostgreSQL. |
| V12 | Pagination et comptage | CONFIRMÉ | total, subtotal, page et per\_page présents ; une page d'une ligne sert à compter. Plafond de per\_page non observable avec 19 hôtes ; environ 47 ms par hôte en liste. |
| V13 | Traces | PARTIELLEMENT CONFIRMÉ | traces\_status dans la liste et endpoint par hôte présents ; aucune trace observée, codage de traces\_status à valider. |
| V14 | Durée en build | NON DISPONIBLE | Aucun début de build exposé (initiated\_at est un candidat non validé) ; seule la VM « en build » est signalée. |
| V15 | Jeton et droits | CONFIRMÉ | Authentification Basic avec jeton personnel et rôle Viewer : 57 appels GET sans refus 403. |

Lien dépôt ↔ CV : le filtre content\_view\_version\_id de /katello/api/repositories liste les dépôts d'une version de CV (9 dépôts pour les versions 9.0 et 10.0 de la CV « Rocky 9 »). Il dit quels dépôts alimentent une CV, pas si leur contenu a changé. Restent à vérifier avant ou pendant le développement :

-
-
- Codage de traces\_status sur une VM ayant un redémarrage en attente.
-
- Début de build (initiated\_at), en observant un vrai build : le champ n'est renseigné que sur 3 hôtes sur 19.
- Plafond de per\_page et durées sur un parc de plusieurs centaines de VMs.
- Composants des CV composites et comportement des CV rolling.
-

Avant la publication, il reste également à vérifier directement la disponibilité du nom katello-inspector sur GitHub, GitLab et PyPI : une première recherche web n'a trouvé aucun projet de ce nom, ce qui ne remplace pas ce contrôle.
