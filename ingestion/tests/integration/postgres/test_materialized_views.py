from copy import deepcopy

from sqlalchemy import create_engine, text

from metadata.generated.schema.entity.data.table import Table, TableType
from metadata.ingestion.ometa.ometa_api import OpenMetadata
from metadata.workflow.metadata import MetadataWorkflow

MATERIALIZED_VIEW_NAME = "om_test_materialized_view"


def test_ingests_materialized_view_when_only_views_are_enabled(
    postgres_container,
    patch_passwords_for_db_services,
    run_workflow,
    ingestion_config,
    db_service,
    metadata: OpenMetadata,
):
    engine = create_engine(postgres_container.get_connection_url())

    with engine.begin() as connection:
        connection.execute(text(f"DROP MATERIALIZED VIEW IF EXISTS {MATERIALIZED_VIEW_NAME}"))
        connection.execute(
            text(
                f"""
                CREATE MATERIALIZED VIEW {MATERIALIZED_VIEW_NAME} AS
                SELECT film_id, title
                FROM film
                LIMIT 10
                """
            )
        )

    config = deepcopy(ingestion_config)
    config["source"]["sourceConfig"]["config"]["includeTables"] = False
    config["source"]["sourceConfig"]["config"]["includeViews"] = True

    try:
        run_workflow(MetadataWorkflow, config)

        materialized_view = metadata.get_by_name(
            Table,
            (
                f"{db_service.fullyQualifiedName.root}."
                f"{postgres_container.dbname}.public.{MATERIALIZED_VIEW_NAME}"
            ),
        )

        assert materialized_view is not None
        assert materialized_view.tableType == TableType.MaterializedView
    finally:
        with engine.begin() as connection:
            connection.execute(text(f"DROP MATERIALIZED VIEW IF EXISTS {MATERIALIZED_VIEW_NAME}"))
        engine.dispose()
