"""Remove ``github-attestation`` and migrate teams to ``sbom-verification``.

The plugin's behaviour has been folded into the unified
``sbom-verification`` plugin (now in the ``attestation`` category). This
migration:

1. Rewrites every ``TeamPluginSettings.enabled_plugins`` list that
   contained ``"github-attestation"`` to reference ``"sbom-verification"``
   instead, deduplicating to avoid double-enabling teams that already
   had both. This keeps existing customers opted-in to attestation
   verification across the rename — they don't have to re-enable.
2. Moves any ``plugin_configs["github-attestation"]`` entry under the
   new key (only if no ``sbom-verification`` config already exists, so
   we never silently overwrite custom settings).
3. Drops the obsolete ``RegisteredPlugin`` row so the orchestrator no
   longer surfaces it in the UI or considers it for category-based
   ``requires_one_of`` lookups.

Historical ``AssessmentRun`` rows tied to
``plugin_name="github-attestation"`` are intentionally preserved — they
remain queryable for audit purposes via the ``run.plugin_name`` field.
"""

from django.db import migrations

OLD_NAME = "github-attestation"
NEW_NAME = "sbom-verification"


def migrate_team_plugin_settings(apps, schema_editor):
    TeamPluginSettings = apps.get_model("plugins", "TeamPluginSettings")
    for settings in TeamPluginSettings.objects.all():
        changed = False

        enabled = list(settings.enabled_plugins or [])
        if OLD_NAME in enabled:
            enabled = [name for name in enabled if name != OLD_NAME]
            if NEW_NAME not in enabled:
                enabled.append(NEW_NAME)
            settings.enabled_plugins = enabled
            changed = True

        configs = dict(settings.plugin_configs or {})
        if OLD_NAME in configs:
            old_config = configs.pop(OLD_NAME)
            # Don't clobber a pre-existing custom config for the new
            # plugin — that would be a silent regression in user state.
            configs.setdefault(NEW_NAME, old_config)
            settings.plugin_configs = configs
            changed = True

        if changed:
            settings.save(update_fields=["enabled_plugins", "plugin_configs", "updated_at"])


def remove_github_attestation_plugin(apps, schema_editor):
    RegisteredPlugin = apps.get_model("plugins", "RegisteredPlugin")
    RegisteredPlugin.objects.filter(name=OLD_NAME).delete()


class Migration(migrations.Migration):
    dependencies = [("plugins", "0012_remove_assessment_run_release_fk")]
    operations = [
        migrations.RunPython(migrate_team_plugin_settings, migrations.RunPython.noop),
        migrations.RunPython(remove_github_attestation_plugin, migrations.RunPython.noop),
    ]
