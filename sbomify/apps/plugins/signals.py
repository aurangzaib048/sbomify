"""Signal handlers for the plugins app."""

from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from sbomify.apps.core.services.transactions import run_on_commit
from sbomify.apps.plugins.tasks import enqueue_assessment, enqueue_assessments_for_existing_sboms_task
from sbomify.logging import getLogger

from .models import AssessmentRun, TeamPluginSettings
from .sdk.enums import RunReason, RunStatus

logger = getLogger(__name__)


@receiver(post_save, sender=TeamPluginSettings)
def trigger_assessments_for_existing_sboms(sender: Any, instance: Any, created: bool, **kwargs: Any) -> None:
    """Trigger assessments for recent SBOMs when plugins are enabled.

    When plugins are enabled for a team, this signal dispatches a background
    task to assess recent SBOMs (within the last 24 hours by default).

    The actual work of querying SBOMs and enqueueing assessments is done in
    a background Dramatiq task to avoid blocking the web server.

    To avoid unnecessary work, this handler only runs when:
    - The instance is created with plugins enabled, or
    - An update explicitly touches the ``enabled_plugins`` field.
    """
    # Determine the current set of enabled plugins
    enabled_plugins = instance.enabled_plugins or []

    if created:
        # On creation, only proceed if plugins are actually enabled
        if not enabled_plugins:
            # No plugins enabled on creation, nothing to do
            return
    else:
        # On update, only proceed if enabled_plugins may have changed
        update_fields = kwargs.get("update_fields")
        if update_fields is not None and "enabled_plugins" not in update_fields:
            # enabled_plugins was not part of this update, nothing to do
            return
        if not enabled_plugins:
            # Plugins have been disabled or are empty, nothing to do
            return

    # Dispatch a background task to handle the bulk work
    # This ensures the web request returns immediately without blocking

    try:
        team = instance.team
        team_id = str(team.id)
        team_key = team.key  # Capture primitive values for safe use in the deferred on-commit callback
        plugin_configs = instance.plugin_configs or {}

        logger.info(
            f"Plugins enabled for team {team_key} ({team_id}). "
            f"Dispatching background task to assess recent SBOMs. Enabled plugins: {enabled_plugins}"
        )

        def _dispatch_bulk_task() -> None:
            enqueue_assessments_for_existing_sboms_task.send(
                team_id=team_id,
                enabled_plugins=enabled_plugins,
                plugin_configs=plugin_configs,
            )
            logger.debug(f"Dispatched bulk assessment task for team {team_key}")

        # Defer until transaction commits to ensure settings are saved
        run_on_commit(_dispatch_bulk_task)

    except AttributeError as e:
        # Missing required attribute (e.g., instance.team doesn't exist)
        team_id = getattr(instance, "team_id", None) or "unknown"
        logger.error(
            f"Missing required attribute when triggering assessments for team {team_id}: {e}",
            exc_info=True,
        )
    except Exception as e:
        # Unexpected error
        team_id = getattr(instance, "team_id", None) or "unknown"
        logger.error(
            f"Unexpected error triggering assessments for existing SBOMs for team {team_id}: {e}",
            exc_info=True,
        )


@receiver(post_save, sender=AssessmentRun)
def trigger_dependents_on_completion(
    sender: Any, instance: AssessmentRun, created: bool, update_fields: Any = None, **kwargs: Any
) -> None:
    """Re-fire dependent plugins when an upstream completes.

    Closes the BSI ↔ sbom-verification race: ``BSI.scan_mode == ONE_SHOT``,
    so it runs immediately on upload and never refreshes — but
    ``sbom-verification`` (attestation-category) is delayed by
    ``ATTESTATION_DELAY_MS`` (currently 120 s) so it doesn't finish until
    well after BSI has already evaluated ``_check_one_of`` against zero
    completed attestation runs. BSI's stored *"No attestation plugin has
    been run for this SBOM"* finding then sits frozen forever.

    When any plugin run flips to ``COMPLETED``, this handler:

    1. Looks up every other enabled plugin whose ``dependencies`` JSON
       references the just-completed plugin's *category* (e.g. BSI's
       ``requires_one_of: [{type: category, value: attestation}]``) or
       its *name*.
    2. For each dependent, checks the most recent completed run of that
       dependent on the same SBOM. If that run finished BEFORE this
       upstream did, the dependent's verdict is provably stale —
       enqueue a fresh run with ``RunReason.DEPENDENCY_CHANGED``.
    3. Skips dependents whose latest run started *after* the upstream
       (so an in-flight retry chain doesn't double-fire).

    The "earlier completed_at" guard makes the handler idempotent and
    bounds retriggering: each upstream completion only refreshes
    dependents whose verdict was actually written before us. A handler
    invocation triggered by the dependent's own completion sees its
    own completed_at as the latest and short-circuits (no infinite loop).
    """
    if instance.status != RunStatus.COMPLETED.value:
        return
    if not instance.completed_at:
        return

    # Defer the dependent enqueue to ``on_commit`` so the just-saved row is
    # visible to the dependents' workers. Avoids a race where the dependent
    # re-runs and queries for the upstream that hasn't been committed yet.
    sbom_id = str(instance.sbom_id)
    upstream_plugin_name = instance.plugin_name
    upstream_category = instance.category
    upstream_completed_at = instance.completed_at

    def _enqueue_dependents() -> None:
        from .models import RegisteredPlugin

        candidates = RegisteredPlugin.objects.filter(is_enabled=True).exclude(name=upstream_plugin_name)
        dependents: list[str] = []
        for plugin in candidates:
            deps = plugin.dependencies or {}
            clauses = list(deps.get("requires_one_of", [])) + list(deps.get("requires_all", []))
            for clause in clauses:
                ctype = clause.get("type")
                cvalue = clause.get("value")
                if (ctype == "category" and cvalue == upstream_category) or (
                    ctype == "plugin" and cvalue == upstream_plugin_name
                ):
                    dependents.append(plugin.name)
                    break

        if not dependents:
            return

        for dep_name in dependents:
            latest = (
                AssessmentRun.objects.filter(
                    sbom_id=sbom_id,
                    plugin_name=dep_name,
                    status=RunStatus.COMPLETED.value,
                )
                .only("plugin_name", "completed_at")
                .order_by("-completed_at")
                .first()
            )
            # If the dependent has never completed, ON_UPLOAD already
            # enqueued a run; let that run on its own schedule rather
            # than enqueueing a competing task.
            if latest is None:
                continue
            # If the dependent's last verdict is more recent than this
            # upstream's, its verdict already saw a completed-or-newer
            # snapshot — no refresh needed. This guard short-circuits
            # the otherwise-infinite ping-pong when the dependent's
            # own completion fires this signal.
            if latest.completed_at and latest.completed_at >= upstream_completed_at:
                continue

            logger.info(
                f"[DEPENDENCY_TRIGGER] Re-enqueueing {dep_name} on SBOM {sbom_id} "
                f"because upstream {upstream_plugin_name} (category={upstream_category}) "
                f"completed at {upstream_completed_at.isoformat()} (dependent's last run "
                f"completed at {latest.completed_at.isoformat() if latest.completed_at else 'unknown'})"
            )
            try:
                enqueue_assessment(
                    sbom_id=sbom_id,
                    plugin_name=dep_name,
                    run_reason=RunReason.DEPENDENCY_CHANGED,
                )
            except Exception:
                # Re-firing dependents is a best-effort UX refresh — log and
                # carry on rather than letting a single dependent's enqueue
                # failure block the upstream's completion path.
                logger.warning(
                    f"[DEPENDENCY_TRIGGER] Failed to enqueue dependent {dep_name} for SBOM {sbom_id}",
                    exc_info=True,
                )

    run_on_commit(_enqueue_dependents)
