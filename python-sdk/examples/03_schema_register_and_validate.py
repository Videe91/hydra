"""Example 03 — register a schema, then preflight-validate payloads.

Hydra's schema gate enforces structure on event payloads. The SDK
gives operators two complementary entry points:

  - `hy.schemas.register_*(...)` — declare structure for a kind
  - `hy.schemas.validate_*(...)` — check a payload BEFORE ingest

Validate methods never raise on `valid: False` — schema mismatch is
the engine's correct verdict, not a transport error. Branch on the
returned `ValidationResponse.valid` and inspect `.errors`.

Requires a Hydra engine with admin scope (the register routes need
`X-Hydra-Tenant` and `admin:schemas`).

Run:

    python examples/03_schema_register_and_validate.py
"""

from __future__ import annotations

import os

from hydra import FieldSchema, HydraSync, ValueTypeOf

BASE_URL = os.environ.get("HYDRA_BASE_URL", "http://localhost:8080")
TOKEN = os.environ.get("HYDRA_TOKEN")
TENANT = os.environ.get("HYDRA_TENANT", "tenant_default")


def main() -> None:
    with HydraSync(BASE_URL, token=TOKEN, tenant=TENANT) as hy:
        # 1. Register a schema for an "Invoice" entity. Two required
        #    primitive fields plus one optional list field, with the
        #    list elements referencing a separate Custom type.
        schema_id = hy.schemas.register_entity(
            type_id="type_invoice",
            name="Invoice",
            fields=[
                FieldSchema(name="amount", value_type="Float", required=True),
                FieldSchema(name="currency", value_type="String", required=True),
                FieldSchema(
                    name="line_items",
                    value_type=ValueTypeOf.list_of(ValueTypeOf.custom("type_lineitem")),
                    required=False,
                ),
            ],
        )
        print(f"1. Registered Invoice schema as {schema_id}")

        # 2. Read it back. The single-fetch endpoints are typed; you
        #    get an `EntityTypeSchema`, not a raw dict.
        schema = hy.schemas.get_entity("type_invoice")
        print(f"2. Schema status: {schema.status}, field count: {len(schema.fields)}")
        for f in schema.fields:
            print(f"     {f.name:<12} {str(f.value_type):<40} required={f.required}")

        # 3. Validate a good payload. We expect valid=True, no errors.
        good = hy.schemas.validate_node_create(
            type_id="type_invoice",
            properties={"amount": 1500.00, "currency": "USD"},
        )
        print(f"\n3. Good payload: valid={good.valid}, errors={len(good.errors)}")

        # 4. Validate a bad payload. The wrong type for `amount` (string
        #    instead of float) and a missing `currency`. The SDK does
        #    NOT raise here — `valid=False` is returned as data.
        bad = hy.schemas.validate_node_create(
            type_id="type_invoice",
            properties={"amount": "not_a_number"},
        )
        print(f"\n4. Bad payload: valid={bad.valid}")
        for err in bad.errors:
            print(f"     {err.path}: {err.message}")


if __name__ == "__main__":
    main()
