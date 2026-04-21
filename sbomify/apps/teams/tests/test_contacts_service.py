"""Unit tests for ``teams.services.contacts`` — the anti-corruption
layer between the compliance app (and any future consumer) and the
teams domain's ``ContactProfile → ContactEntity → ContactProfileContact``
layout.

Covers tenant isolation: accessors must not return entities/contacts
from another team even when the database contains qualifying rows for
a different tenant.
"""

from __future__ import annotations

import pytest

from sbomify.apps.teams.models import (
    ContactEntity,
    ContactProfile,
    ContactProfileContact,
    Team,
)
from sbomify.apps.teams.services.contacts import (
    contact_belongs_to_team,
    get_manufacturer,
    get_security_contact,
    list_workspace_contacts,
)


def _make_team(name: str) -> Team:
    return Team.objects.create(name=name)


def _make_profile(team: Team, name: str = "Default", *, private: bool = False) -> ContactProfile:
    return ContactProfile.objects.create(team=team, name=name, is_component_private=private)


def _make_manufacturer(profile: ContactProfile, name: str = "Acme Corp") -> ContactEntity:
    entity = ContactEntity(
        profile=profile,
        name=name,
        email=f"contact@{name.lower().replace(' ', '')}.example",
        is_manufacturer=True,
    )
    entity.save()
    return entity


def _make_contact(
    entity: ContactEntity,
    name: str,
    *,
    is_security: bool = False,
) -> ContactProfileContact:
    slug = name.lower().replace(" ", "-")
    contact = ContactProfileContact(
        entity=entity,
        name=name,
        email=f"{slug}@example.test",
        is_security_contact=is_security,
    )
    contact.save()
    return contact


@pytest.mark.django_db
class TestGetManufacturer:
    def test_returns_flagged_entity_for_team(self):
        team = _make_team("Tenant A")
        profile = _make_profile(team)
        entity = _make_manufacturer(profile, "Tenant A Manufacturer")

        assert get_manufacturer(team) == entity

    def test_returns_none_when_no_manufacturer_flagged(self):
        team = _make_team("Tenant A")
        profile = _make_profile(team)
        supplier = ContactEntity(
            profile=profile,
            name="Supplier Only",
            email="s@example.test",
            is_supplier=True,
        )
        supplier.save()

        assert get_manufacturer(team) is None

    def test_tenant_isolation(self):
        """Two teams each with a manufacturer — the accessor must not
        cross-contaminate. Regression guard for the ACL refactor."""
        team_a = _make_team("Tenant A")
        team_b = _make_team("Tenant B")
        mfr_a = _make_manufacturer(_make_profile(team_a), "Acme A")
        mfr_b = _make_manufacturer(_make_profile(team_b), "Acme B")

        assert get_manufacturer(team_a) == mfr_a
        assert get_manufacturer(team_b) == mfr_b

    def test_finds_manufacturer_in_non_default_profile(self):
        """Manufacturer can live in any profile scoped to the team,
        not just the default one — documented behaviour in the
        accessor docstring."""
        team = _make_team("Tenant A")
        _make_profile(team, name="Default")
        secondary = _make_profile(team, name="Secondary")
        entity = _make_manufacturer(secondary, "Secondary Manufacturer")

        assert get_manufacturer(team) == entity


@pytest.mark.django_db
class TestGetSecurityContact:
    def test_returns_flagged_contact_for_team(self):
        team = _make_team("Tenant A")
        mfr = _make_manufacturer(_make_profile(team))
        contact = _make_contact(mfr, "Secops", is_security=True)

        assert get_security_contact(team) == contact

    def test_returns_none_when_no_security_contact_flagged(self):
        team = _make_team("Tenant A")
        mfr = _make_manufacturer(_make_profile(team))
        _make_contact(mfr, "Alice", is_security=False)

        assert get_security_contact(team) is None

    def test_tenant_isolation(self):
        team_a = _make_team("Tenant A")
        team_b = _make_team("Tenant B")
        mfr_a = _make_manufacturer(_make_profile(team_a), "Acme A")
        mfr_b = _make_manufacturer(_make_profile(team_b), "Acme B")
        sec_a = _make_contact(mfr_a, "Sec A", is_security=True)
        sec_b = _make_contact(mfr_b, "Sec B", is_security=True)

        assert get_security_contact(team_a) == sec_a
        assert get_security_contact(team_b) == sec_b


@pytest.mark.django_db
class TestListWorkspaceContacts:
    def test_returns_public_profile_contacts(self):
        team = _make_team("Tenant A")
        mfr = _make_manufacturer(_make_profile(team))
        _make_contact(mfr, "Alice")
        _make_contact(mfr, "Bob")

        result = list_workspace_contacts(team)

        assert len(result) == 2
        assert {row["name"] for row in result} == {"Alice", "Bob"}
        row = result[0]
        assert set(row.keys()) == {"id", "name", "email", "phone", "profile_name"}
        assert row["profile_name"] == "Default"

    def test_excludes_component_private_profiles(self):
        """Component-private profiles are scoped to a single component
        and must not appear in the workspace support-contact dropdown."""
        team = _make_team("Tenant A")
        public_mfr = _make_manufacturer(_make_profile(team, name="Public"))
        private_mfr = _make_manufacturer(_make_profile(team, name="Private", private=True), "Private Mfr")
        _make_contact(public_mfr, "Public Contact")
        _make_contact(private_mfr, "Private Contact")

        result = list_workspace_contacts(team)

        assert {row["name"] for row in result} == {"Public Contact"}

    def test_tenant_isolation(self):
        team_a = _make_team("Tenant A")
        team_b = _make_team("Tenant B")
        mfr_a = _make_manufacturer(_make_profile(team_a), "Acme A")
        mfr_b = _make_manufacturer(_make_profile(team_b), "Acme B")
        _make_contact(mfr_a, "Contact A")
        _make_contact(mfr_b, "Contact B")

        result_a = list_workspace_contacts(team_a)
        result_b = list_workspace_contacts(team_b)

        assert {row["name"] for row in result_a} == {"Contact A"}
        assert {row["name"] for row in result_b} == {"Contact B"}


@pytest.mark.django_db
class TestContactBelongsToTeam:
    def test_true_when_contact_scoped_to_team(self):
        team = _make_team("Tenant A")
        mfr = _make_manufacturer(_make_profile(team))
        contact = _make_contact(mfr, "Alice")

        assert contact_belongs_to_team(contact.id, team) is True

    def test_false_when_contact_from_different_team(self):
        """Tenant-isolation regression — the CRA wizard rejects a
        support_contact_id from another workspace."""
        team_a = _make_team("Tenant A")
        team_b = _make_team("Tenant B")
        mfr_a = _make_manufacturer(_make_profile(team_a), "Acme A")
        _make_manufacturer(_make_profile(team_b), "Acme B")
        contact_a = _make_contact(mfr_a, "A Contact")

        assert contact_belongs_to_team(contact_a.id, team_b) is False

    def test_false_for_unknown_id(self):
        team = _make_team("Tenant A")

        assert contact_belongs_to_team("does-not-exist", team) is False
