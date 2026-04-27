"""Remove the standalone ``github-attestation`` plugin record.

The plugin's behaviour has been folded into the unified
``sbom-verification`` plugin (now in the ``attestation`` category). This
migration drops the obsolete ``RegisteredPlugin`` row so the orchestrator
no longer surfaces it in the UI or considers it for category-based
``requires_one_of`` lookups. Historical ``AssessmentRun`` rows tied to
``plugin_name="github-attestation"`` are intentionally preserved — they
remain queryable for audit purposes via the ``run.plugin_name`` field.
"""

from django.db import migrations


def remove_github_attestation_plugin(apps, schema_editor):
    RegisteredPlugin = apps.get_model("plugins", "RegisteredPlugin")
    RegisteredPlugin.objects.filter(name="github-attestation").delete()


class Migration(migrations.Migration):
    dependencies = [("plugins", "0012_remove_assessment_run_release_fk")]
    operations = [migrations.RunPython(remove_github_attestation_plugin, migrations.RunPython.noop)]
