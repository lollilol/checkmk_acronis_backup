#!/usr/bin/env python3
"""Builds the command line of the Acronis Cyber Protect Cloud special agent."""

from collections.abc import Iterator, Sequence

from pydantic import BaseModel

from cmk.server_side_calls.v1 import HostConfig, Secret, SpecialAgentCommand, SpecialAgentConfig


class AcronisBackupParams(BaseModel):
    url: str
    client_id: str
    client_secret: Secret
    lookback_days: int = 3
    piggyback_lowercase: bool = True
    piggyback_strip_domains: Sequence[str] = ()


def _commands(
    params: AcronisBackupParams, host_config: HostConfig
) -> Iterator[SpecialAgentCommand]:
    args: list[str | Secret] = [
        "--url",
        params.url,
        "--client-id",
        params.client_id,
        "--client-secret-id",
        params.client_secret,
        "--lookback-hours",
        str(params.lookback_days * 24),
        "--hostname",
        host_config.name,
    ]
    if not params.piggyback_lowercase:
        args.append("--keep-case")
    for domain in params.piggyback_strip_domains:
        args += ["--strip-domain", domain]
    yield SpecialAgentCommand(command_arguments=args)


special_agent_acronis_backup = SpecialAgentConfig(
    name="acronis_backup",
    parameter_parser=AcronisBackupParams.model_validate,
    commands_function=_commands,
)
