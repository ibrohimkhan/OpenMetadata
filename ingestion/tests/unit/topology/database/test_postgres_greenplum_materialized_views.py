#  Copyright 2025 Collate
#  Licensed under the Collate Community License, Version 1.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  https://github.com/open-metadata/OpenMetadata/blob/main/ingestion/LICENSE
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from metadata.generated.schema.entity.data.table import TableType
from metadata.ingestion.source.database.common_db_source import (
    CommonDbSourceService,
    TableNameAndType,
)
from metadata.ingestion.source.database.greenplum.metadata import GreenplumSource
from metadata.ingestion.source.database.postgres.metadata import PostgresSource


class _Inspector:
    def get_view_names(self, schema_name):
        return ["plain_view"]

    def get_materialized_view_names(self, schema_name):
        return ["materialized_view"]


def _source_with_inspector(source_cls):
    probe_cls = type(
        f"Probe{source_cls.__name__}",
        (source_cls,),
        {"inspector": _Inspector()},
    )
    return probe_cls.__new__(probe_cls)


@pytest.mark.parametrize("source_cls", [PostgresSource, GreenplumSource])
def test_query_view_names_and_types_includes_materialized_views(source_cls):
    source = _source_with_inspector(source_cls)

    assert list(source.query_view_names_and_types("public")) == [
        TableNameAndType(name="plain_view", type_=TableType.View),
        TableNameAndType(name="materialized_view", type_=TableType.MaterializedView),
    ]


def _source_probe(include_tables: bool, include_views: bool):
    context_value = SimpleNamespace(
        database_schema="public",
        database_service="test_service",
        database="test_database",
    )
    table_query = MagicMock(
        return_value=[TableNameAndType(name="regular_table", type_=TableType.Regular)]
    )
    view_query = MagicMock(
        return_value=[
            TableNameAndType(
                name="materialized_view",
                type_=TableType.MaterializedView,
            )
        ]
    )

    source = SimpleNamespace(
        source_config=SimpleNamespace(
            includeTables=include_tables,
            includeViews=include_views,
            tableFilterPattern=None,
            useFqnForFiltering=False,
        ),
        context=SimpleNamespace(get=lambda: context_value),
        metadata=MagicMock(),
        status=MagicMock(),
        standardize_table_name=lambda _schema_name, table_name: table_name,
        query_table_names_and_types=table_query,
        query_view_names_and_types=view_query,
    )
    return source, table_query, view_query


def test_materialized_view_is_emitted_when_only_views_are_enabled():
    source, table_query, view_query = _source_probe(
        include_tables=False,
        include_views=True,
    )

    with (
        patch(
            "metadata.ingestion.source.database.common_db_source.fqn.build",
            return_value="test_fqn",
        ),
        patch(
            "metadata.ingestion.source.database.common_db_source.filter_by_table",
            return_value=False,
        ),
    ):
        assert list(CommonDbSourceService.get_tables_name_and_type(source)) == [
            ("materialized_view", TableType.MaterializedView)
        ]

    table_query.assert_not_called()
    view_query.assert_called_once_with("public")


def test_materialized_view_is_not_emitted_when_views_are_disabled():
    source, table_query, view_query = _source_probe(
        include_tables=True,
        include_views=False,
    )

    with (
        patch(
            "metadata.ingestion.source.database.common_db_source.fqn.build",
            return_value="test_fqn",
        ),
        patch(
            "metadata.ingestion.source.database.common_db_source.filter_by_table",
            return_value=False,
        ),
    ):
        assert list(CommonDbSourceService.get_tables_name_and_type(source)) == [
            ("regular_table", TableType.Regular)
        ]

    table_query.assert_called_once_with("public")
    view_query.assert_not_called()
