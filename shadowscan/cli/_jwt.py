"""jwt command."""

from __future__ import annotations

import sys
from typing import Any

import click

import shadowscan.cli as _cli
from shadowscan.cli import ScanOptions, _warn_argv_secret, main, scan_options
from shadowscan.config import ConnectorSpec


# ----------------------------------------------------------------------- jwt
@main.command()
@click.argument("tokens", nargs=-1)
@click.option(
    "--file",
    "-F",
    "token_file",
    type=click.Path(exists=True, dir_okay=False),
    help="file with one JWT per line or a JSON list",
)
@click.option("--jwks-url", help="verify signatures against this trusted JWKS endpoint")
@click.option("--expected-issuer", help="require this exact issuer when checking a JWT signature")
@click.option(
    "--jwt-algorithm",
    multiple=True,
    type=click.Choice(["RS256", "ES256", "EdDSA", "PS256"]),
    help="narrow allowed signature algorithms (repeatable)",
)
@scan_options
def jwt(
    tokens: tuple[str, ...],
    token_file: str | None,
    jwks_url: str | None,
    expected_issuer: str | None,
    jwt_algorithm: tuple[str, ...],
    opts: ScanOptions,
) -> None:
    """Classify JWTs as human / service / delegated-agent identities and assess their privileges."""
    conf: dict[str, Any] = {}
    if tokens:
        _warn_argv_secret("JWT arguments", "--file or stdin")
        conf["tokens"] = [t.strip().removeprefix("Bearer ").strip() for t in tokens]
    if token_file:
        conf["input"] = token_file
    if expected_issuer or jwt_algorithm:
        if not jwks_url:
            raise click.UsageError("--expected-issuer and --jwt-algorithm require --jwks-url")
    if jwks_url:
        conf["jwks_url"] = jwks_url
    if expected_issuer:
        conf["expected_issuer"] = expected_issuer
    if jwt_algorithm:
        conf["allowed_algorithms"] = list(jwt_algorithm)
    if not conf.get("tokens") and not conf.get("input"):
        if not sys.stdin.isatty():
            conf["tokens"] = [line.strip() for line in sys.stdin if line.strip()]
        else:
            raise click.UsageError("give tokens as arguments, --file, or on stdin")
    _cli._run_scan(opts.config([ConnectorSpec(name="identity.jwt", config=conf)]), opts)
