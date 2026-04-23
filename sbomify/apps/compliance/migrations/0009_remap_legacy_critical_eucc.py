"""Remap legacy ``critical`` + ``eucc`` CRA assessments to ``module_b_c``.

PR #861 removes EUCC from the default conformity-procedure mapping for
Critical products because EUCC is not yet mandated (CRA Art 8(1)) — the
new default is Module B+C (CRA Art 32(3)). Existing rows persisted
before this change retain the now-invalid combination and would still
render ``EUCC`` into the Declaration of Conformity on export. Snap
those rows to the new default as a one-shot data migration.

Idempotent: rows that already use a permitted procedure are untouched.
Reverse is a no-op — losing the original ``eucc`` marker is preferable
to silently re-applying the wrong procedure on rollback.
"""

from __future__ import annotations

from django.db import migrations


def remap_critical_eucc(apps, schema_editor):
    CRAAssessment = apps.get_model("compliance", "CRAAssessment")
    CRAAssessment.objects.filter(
        product_category="critical",
        conformity_assessment_procedure="eucc",
    ).update(conformity_assessment_procedure="module_b_c")


class Migration(migrations.Migration):

    dependencies = [
        ("compliance", "0008_refine_scope_screening_help_text"),
    ]

    operations = [
        migrations.RunPython(remap_critical_eucc, migrations.RunPython.noop),
    ]
