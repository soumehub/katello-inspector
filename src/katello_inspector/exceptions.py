from __future__ import annotations


class InspectorError(Exception):
    """Base commune pour les erreurs connues de l'outil."""


class UsageError(InspectorError):
    """Option ou configuration invalide (code 2 en mode manuel)."""


class ConfigError(UsageError):
    """Fichier INI, seuils ou jeton invalides."""


class ApiError(InspectorError):
    """Echec d'un appel a l'API (reseau, TLS, timeout, reponse inattendue)."""


class UnsupportedSearchError(ApiError):
    """Champ de recherche non reconnu par l'API (HTTP 500 sur les hotes, 400 sur les taches)."""
