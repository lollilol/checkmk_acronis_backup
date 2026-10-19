#!/usr/bin/env python3
"""Setup rule: parameters of the two Acronis backup checks.

Both services use this one rule set. It has one block of settings per service,
and a service ignores the block of the other one. A block is optional, so that
a rule for the machines does not override the settings of the summary. Within
a block all settings are shown, pre-filled with the defaults of the check.
"""

from collections.abc import Mapping

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    InputHint,
    Integer,
    LevelDirection,
    LevelsType,
    List,
    ServiceState,
    SimpleLevels,
    String,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.form_specs.validators import LengthInRange, NumberInRange
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic

_MACHINE_KEYS = ("age_levels", "state_warning", "state_cancelled", "state_no_plan")
_SUMMARY_KEYS = ("levels_with_plan", "levels_without_plan", "required_machines", "state_missing")


def _migrate(value: object) -> Mapping[str, object]:
    """Versions 1.3.0 and 1.3.1 stored all settings side by side."""
    if not isinstance(value, dict):
        return {}
    if not any(key in value for key in _MACHINE_KEYS + _SUMMARY_KEYS):
        return value
    blocks = {
        "machine": {key: value[key] for key in _MACHINE_KEYS if key in value},
        "summary": {key: value[key] for key in _SUMMARY_KEYS if key in value},
    }
    return {name: settings for name, settings in blocks.items() if settings}


def _count() -> Integer:
    return Integer(custom_validate=[NumberInRange(min_value=0)])


def _machine() -> Dictionary:
    return Dictionary(
        title=Title("Backup of a machine"),
        help_text=Help("Settings of the service 'Acronis Backup' of the single machines."),
        elements={
            "age_levels": DictElement(
                required=True,
                parameter_form=SimpleLevels(
                    title=Title("Time since the last successful backup"),
                    help_text=Help(
                        "Based on the newest successful run of all backup plans that are "
                        "applied to the machine."
                    ),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.DAY, TimeMagnitude.HOUR]
                    ),
                    prefill_fixed_levels=DefaultValue((129600.0, 259200.0)),
                ),
            ),
            "state_warning": DictElement(
                required=True,
                parameter_form=ServiceState(
                    title=Title("State if the last run finished with warnings"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_cancelled": DictElement(
                required=True,
                parameter_form=ServiceState(
                    title=Title("State if the last run was cancelled"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_no_plan": DictElement(
                required=True,
                parameter_form=ServiceState(
                    title=Title("State if no backup plan is applied any more"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
        },
    )


def _summary() -> Dictionary:
    return Dictionary(
        title=Title("Overview of all machines"),
        help_text=Help(
            "Settings of the service 'Acronis Backup Summary' on the host of the special agent."
        ),
        elements={
            "levels_with_plan": DictElement(
                required=True,
                parameter_form=SimpleLevels(
                    title=Title("Minimum number of machines with a backup plan"),
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=_count(),
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    prefill_fixed_levels=InputHint((0, 0)),
                ),
            ),
            "levels_without_plan": DictElement(
                required=True,
                parameter_form=SimpleLevels(
                    title=Title("Maximum number of machines without a backup plan"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=_count(),
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    prefill_fixed_levels=InputHint((0, 0)),
                ),
            ),
            "required_machines": DictElement(
                required=True,
                parameter_form=List(
                    title=Title("Machines that must have a backup plan"),
                    help_text=Help(
                        "The service changes its state if one of these machines has no "
                        "backup plan applied or is not known to Acronis at all. Enter the "
                        "names as they are listed in the details of the service, that is "
                        "after the conversion of the machine names by the special agent. "
                        "Upper and lower case do not matter."
                    ),
                    element_template=String(custom_validate=[LengthInRange(min_value=1)]),
                    add_element_label=Label("Add machine"),
                    editable_order=False,
                ),
            ),
            "state_missing": DictElement(
                required=True,
                parameter_form=ServiceState(
                    title=Title("State if one of these machines has no backup plan"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
        },
    )


def _form() -> Dictionary:
    return Dictionary(
        migrate=_migrate,
        elements={
            "machine": DictElement(parameter_form=_machine()),
            "summary": DictElement(parameter_form=_summary()),
        },
    )


rule_spec_acronis_backup = CheckParameters(
    name="acronis_backup",
    title=Title("Acronis backup"),
    topic=Topic.STORAGE,
    parameter_form=_form,
    condition=HostCondition(),
)
