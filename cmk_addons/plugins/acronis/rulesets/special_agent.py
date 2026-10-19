#!/usr/bin/env python3
"""Setup rule: Acronis Cyber Protect Cloud special agent."""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    InputHint,
    Integer,
    List,
    Password,
    String,
)
from cmk.rulesets.v1.form_specs.validators import LengthInRange, NumberInRange, Url, UrlProtocol
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _form() -> Dictionary:
    return Dictionary(
        title=Title("Acronis Cyber Protect Cloud"),
        help_text=Help(
            "Queries the Acronis Cyber Protect Cloud API and creates piggyback data with the "
            "backup status of every machine. Assign this rule to one host that represents "
            "the Acronis tenant. The machines must exist as hosts in Checkmk under the name "
            "the agent derives from the Acronis machine name."
        ),
        elements={
            "url": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Data center URL"),
                    help_text=Help(
                        "The data center URL that Acronis shows when the API client is "
                        "created, without a path, for example https://eu2-cloud.acronis.com"
                    ),
                    prefill=InputHint("https://eu2-cloud.acronis.com"),
                    custom_validate=[Url([UrlProtocol.HTTPS])],
                ),
            ),
            "client_id": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("API client ID"),
                    custom_validate=[LengthInRange(min_value=1)],
                ),
            ),
            "client_secret": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API client secret"),
                    custom_validate=[LengthInRange(min_value=1)],
                ),
            ),
            "lookback_days": DictElement(
                required=True,
                parameter_form=Integer(
                    title=Title("Evaluate finished runs of the last"),
                    help_text=Help(
                        "The result (OK, warning, error) of the most recent finished run is "
                        "taken from the Acronis task list of this period. It should be at "
                        "least as long as the longest gap between two scheduled backups."
                    ),
                    unit_symbol="days",
                    prefill=DefaultValue(3),
                    custom_validate=[NumberInRange(min_value=1, max_value=31)],
                ),
            ),
            "piggyback_lowercase": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    title=Title("Piggyback host names"),
                    label=Label("Convert Acronis machine names to lower case"),
                    prefill=DefaultValue(True),
                ),
            ),
            "piggyback_strip_domains": DictElement(
                required=True,
                parameter_form=List(
                    title=Title("Remove these domains from the machine names"),
                    help_text=Help(
                        "Machines with an Acronis agent are registered under their full "
                        "name. Enter the domains that are not part of the host names in "
                        "Checkmk: with example.local, the machine server.example.local "
                        "is assigned to the host server."
                    ),
                    element_template=String(custom_validate=[LengthInRange(min_value=1)]),
                    add_element_label=Label("Add domain"),
                    editable_order=False,
                ),
            ),
        },
    )


rule_spec_special_agent_acronis_backup = SpecialAgent(
    name="acronis_backup",
    title=Title("Acronis Cyber Protect Cloud"),
    topic=Topic.CLOUD,
    parameter_form=_form,
)
