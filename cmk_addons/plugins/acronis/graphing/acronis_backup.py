#!/usr/bin/env python3
"""Metrics of the service 'Acronis Backup Summary'."""

from cmk.graphing.v1 import Title
from cmk.graphing.v1.metrics import Color, DecimalNotation, Metric, StrictPrecision, Unit

_COUNT = Unit(DecimalNotation(""), StrictPrecision(0))

metric_acronis_machines_with_plan = Metric(
    name="acronis_machines_with_plan",
    title=Title("Machines with backup plan"),
    unit=_COUNT,
    color=Color.GREEN,
)

metric_acronis_machines_without_plan = Metric(
    name="acronis_machines_without_plan",
    title=Title("Machines without backup plan"),
    unit=_COUNT,
    color=Color.ORANGE,
)
