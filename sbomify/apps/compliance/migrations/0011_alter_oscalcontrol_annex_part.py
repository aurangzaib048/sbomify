"""Restrict ``annex_part`` to the two canonical values.

Previously the field was a free-form ``CharField(max_length=10)``
with only a ``default`` and the 0010 ``CheckConstraint`` guarding the
``is_mandatory == (annex_part == "part-ii")`` biconditional. An invalid
string like ``"part-iii"`` would land with ``is_mandatory=False`` and
pass the constraint (because both sides of the disjunction evaluate
false), silently degrading Part II handling for any control where the
import path produced a typo.

Adding the ``AnnexPart`` TextChoices pulls the allowed values into
the model layer so admin dropdowns, form clean(), and serializer
introspection all enforce the invariant — the DB constraint continues
to enforce the pairing, but the field now refuses unknown values at
every Django entry point.
"""

from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("compliance", "0010_oscalcontrol_is_mandatory_iff_part_ii"),
    ]

    operations = [
        migrations.AlterField(
            model_name="oscalcontrol",
            name="annex_part",
            field=models.CharField(
                choices=[
                    ("part-i", "Part I (Essential requirements)"),
                    ("part-ii", "Part II (Vulnerability handling)"),
                ],
                default="part-i",
                help_text="Which part of CRA Annex I this control belongs to (part-i or part-ii)",
                max_length=10,
            ),
        ),
    ]
