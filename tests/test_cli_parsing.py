"""Comportement du parseur lui-meme, independamment des codes retour.

Les options globales utilisent `default=argparse.SUPPRESS` pour fonctionner
avant et apres le nom de la sous-commande (voir le commentaire dans cli.py).
Consequence : un attribut absent du Namespace n'est pas une erreur, le reste
du code utilise toujours `getattr(args, "x", defaut)` pour retrouver le
defaut documente dans le cadrage.
"""
from __future__ import annotations

from katello_inspector.cli import build_parser


def test_absent_attributes_fall_back_to_their_documented_default() -> None:
    args = build_parser().parse_args(["version"])
    assert not hasattr(args, "monitoring")
    assert getattr(args, "monitoring", False) is False
    assert not hasattr(args, "url")
    assert getattr(args, "url", None) is None
    assert not hasattr(args, "insecure")
    assert getattr(args, "insecure", False) is False
    assert not hasattr(args, "format")
    assert getattr(args, "format", "text") == "text"


def test_monitoring_gives_the_same_result_before_or_after_the_subcommand() -> None:
    parser = build_parser()
    before = parser.parse_args(["--monitoring", "version"])
    after = parser.parse_args(["version", "--monitoring"])
    assert before.monitoring is True
    assert after.monitoring is True


def test_monitoring_absent_everywhere_gives_the_same_result_both_ways() -> None:
    parser = build_parser()
    args = parser.parse_args(["version"])
    assert getattr(args, "monitoring", False) is False
