"""Team-scoped contact accessors.

Single source of truth for "which entity plays role X for this team?"
Consumers — currently the CRA compliance pipeline (document generation,
export packaging, wizard step builders, auto-fill) — call these
helpers instead of filtering ``ContactEntity`` / ``ContactProfileContact``
directly against ``profile__team`` / ``entity__profile__team``. That
keeps the "find the manufacturer / security contact" rule in one place
and lets the teams app own the model layout (``ContactProfile`` →
``ContactEntity`` → ``ContactProfileContact``) without other apps
having to know it.

Anti-Corruption Layer in the spirit of
https://martinfowler.com/bliki/AntiCorruptionLayer.html: compliance
stays a consumer of teams' domain and doesn't need to grow knowledge
of teams' internal schema.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sbomify.apps.teams.models import ContactEntity, ContactProfileContact

if TYPE_CHECKING:
    from sbomify.apps.teams.models import Team


def get_manufacturer(team: Team) -> ContactEntity | None:
    """Return the team's configured manufacturer entity, or None.

    Walks ``ContactProfile → ContactEntity`` — the entity is scoped to
    any profile within the team, not pinned to the default profile.
    Returns the first match found if multiple entities are flagged
    (data-model shouldn't allow multiple manufacturers per team but the
    accessor stays resilient to that).
    """
    return ContactEntity.objects.filter(
        profile__team=team,
        is_manufacturer=True,
    ).first()


def get_security_contact(team: Team) -> ContactProfileContact | None:
    """Return the team's designated security contact, or None.

    Walks ``ContactProfile → ContactEntity → ContactProfileContact``
    so the contact can live under any profile within the team. Used
    by the CRA wizard to auto-fill ``csirt_contact_email`` on a new
    assessment (Article 14) and by the DoC renderer for the inline
    security-contact line on user instructions.
    """
    return (
        ContactProfileContact.objects.filter(
            entity__profile__team=team,
            is_security_contact=True,
        )
        .select_related("entity")
        .first()
    )
