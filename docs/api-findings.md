# Constats sur l'API (Katello 4.21.1.1 / Foreman 3.19.1)

Observés le 16 novembre 2026 avec un compte Viewer, en GET uniquement, sur une instance de 19 hôtes, 9 CV, 3 environnements (Library, Staging, Production). Un champ existant ne prouve pas son sens : ce qui a été comparé à l'interface est indiqué.

## Authentification et plateforme
- HTTP Basic avec le nom du compte et un jeton personnel. Le rôle Viewer suffit : aucun 403 sur les endpoints utilisés.
- `/api/status` donne la version de Foreman (3.19.1) ; `/katello/api/status` celle de Katello (4.21.1.1).
- `/katello/api/ping` donne `services.*.status` (candlepin, candlepin_auth, foreman_tasks, katello_events, pulp3, pulp3_content).
- Pulp : `/pulp/api/v3/status/`, `storage.total|used|free` en octets, comparés à `df` sur le filesystem de Pulp (correspondance exacte). Lisible sans authentification. Hors API Foreman.

## Pagination
- Réponse : `total`, `subtotal`, `page`, `per_page`, `results`.
- `per_page=1` sert à compter (150 à 250 ms). `per_page=500` accepté ; plafond non observable avec 19 hôtes.
- Environ 47 ms par hôte sur une page de liste (extrapolation, à confirmer sur un grand parc).
- `thin=true` ne renvoie que id et name.

## Recherche sur /api/hosts
- Acceptés : `last_checkin`, `errata_status`, `trace_status`, `build`, `lifecycle_environment`, `content_view`.
- Rejeté : `subscription_status`.
- Champ inconnu : **HTTP 500** avec « Field '…' not recognized for searching! » (ne pas retenter). Sur `/foreman_tasks/api/tasks` c'est un 400.
- Une recherche acceptée prouve que le champ est reconnu, pas que la valeur testée est valide.

## Liste des hôtes (`/api/hosts`)
Chemins vérifiés (entre `content_facet_attributes.` et le reste) :

| Donnée | Chemin |
| --- | --- |
| Dernier check-in | `subscription_facet_attributes.last_checkin` |
| Errata installables | `content_facet_attributes.errata_counts.{security,bugfix,enhancement,total}` |
| Errata applicables | `content_facet_attributes.errata_counts.applicable.{security,bugfix,enhancement,total}` |
| Paquets | `content_facet_attributes.applicable_package_count`, `upgradable_package_count` |
| Couples CV et environnement | `content_facet_attributes.content_view_environments[]` |
| Libellés | `content_facet_attributes.content_view_environment_labels` (ex. `Production/cv-a,Production/cv-b`) |
| Content source | `content_facet_attributes.content_source.{id,name}` |
| Statut errata | `errata_status` (entier), `errata_status_label` |
| Statut traces | `traces_status` (0 = « No processes require restarting »), `traces_status_label` ; codage d'une trace en attente non observé |
| Build | `build`, `build_status`, `build_status_label` |

Dans chaque élément de `content_view_environments[]` :
- `content_view.id`, `content_view.composite`, `content_view.rolling`
- `content_view.content_view_version` (ex. `2.0`), `content_view.content_view_version_id`, `content_view.content_view_version_latest`
- `lifecycle_environment.id`, `.name`, `.label`, `.lifecycle_environment_library`

La version servie est **dans `content_view`**, pas dans un objet `content_view_version` séparé. Elle a été comparée à l'interface sur un hôte à deux CV.

Un hôte sur 19 n'a pas de données de contenu (champs null) : il doit donner N/A ou UNKNOWN selon le cadrage, jamais OK.

Errata : les compteurs `errata_counts` (installables) et `errata_counts.applicable` ont été comparés à l'interface pour security (1 installable, 20 applicables sur un hôte) et bugfix (1 et 1 sur un autre). Enhancement : non comparé (aucun en attente). Les paramètres `errata_restrict_*` de `/api/hosts/:id/errata` n'ont rien changé aux totaux : ne pas les utiliser.

## Errata détaillés
- `/api/hosts/:id/errata` : `errata_id`, `id`, `issued`, `severity`, `title`, `type`, `updated`. Réservé à la sous-commande `host`.
- Sévérités : Critical, Important, Moderate, Low, et la valeur littérale `"None"` (2 errata security sur 186) : à traiter comme inconnue.

## CV, versions, environnements
- `/katello/api/content_view_versions` : `created_at` = date de publication (comparé à l'interface) ; `last_event.created_at` = dernier événement (une promotion dans le cas testé) ; `environments[].{id,host_count,hostgroup_count,activation_key_count}`.
- `/katello/api/content_views` : `composite`, `rolling`, `needs_publish`, `last_published`, `latest_version`, `latest_version_environments[]`. Aucune CV composite ni rolling sur l'instance : composants et comportement non observés.
- `/katello/api/environments` : `prior`, `successor` donnent l'ordre de promotion.
- Version pour un couple : `/katello/api/content_view_versions?content_view_id=X&environment_id=Y`.
- Dépôts d'une version : `/katello/api/repositories?content_view_version_id=N` (une même version peut lister plusieurs fois le même dépôt, par exemple epel).

## Dépôts et produits
- `/katello/api/repositories` : `last_sync.{started_at,ended_at,result,state}` (absent pour les dépôts sans URL source, 4 sur 20), `content_counts.*`. Aucun indicateur de changement de contenu : seulement des compteurs.
- `/katello/api/products` : `last_sync`, `sync_plan.*`.

## Tâches (`/foreman_tasks/api/tasks`)
- Recherche par `state`, `result`, `started_at` acceptée.
- Libellés : `Actions::Katello::Repository::Sync`, `Actions::Katello::SyncPlan::Run`, `Actions::Katello::ContentView::Publish`, `Actions::Katello::ContentView::Promote`.
- `input` d'une publication : `content_view.id`, `content_view_version_id`. D'une promotion : `content_view.id`, `environments[]`. D'une synchronisation : `repository.id`, `product.id`.

## Non disponible
- Date du profil de paquets (seuls des horodatages génériques existent).
- Début de build : `initiated_at` n'est renseigné que sur 3 hôtes sur 19 et n'a pas été validé sur un vrai build.
- Statut global Foreman : trompeur, écarté.
