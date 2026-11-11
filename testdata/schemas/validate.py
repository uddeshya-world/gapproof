"""Validate Gapproof output against the vendored official JSON schemas.

Test infrastructure only (never shipped, never run by the product). It runs
inside python:3.12-slim with pinned jsonschema and regex packages:

    python -I validate.py cyclonedx <schemas-dir> <file>...
    python -I validate.py oscal-ar  <schemas-dir> <file>...

All $refs resolve to the vendored files; nothing is fetched. OSCAL patterns
use \\p{L}/\\p{N}, which Python's `re` lacks, so `pattern` is evaluated with
the `regex` module, which supports Unicode property classes.
"""

import json
import os
import sys

import jsonschema
import regex
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7


def _pattern(validator, patrn, instance, schema):
    if validator.is_type(instance, "string") and not regex.search(patrn, instance):
        yield jsonschema.ValidationError(f"{instance!r} does not match {patrn!r}")


def _is_regex(s):
    if isinstance(s, str):
        regex.compile(s)
    return True


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    kind, schemas, files = sys.argv[1], sys.argv[2], sys.argv[3:]
    if kind == "cyclonedx":
        d = os.path.join(schemas, "cyclonedx-1.6")
        main_name = "bom-1.6.schema.json"
        names = [main_name, "spdx.schema.json", "jsf-0.82.schema.json"]
    elif kind == "oscal-ar":
        d = os.path.join(schemas, "oscal-1.1.2")
        main_name = "oscal_assessment-results_schema.json"
        names = [main_name]
    else:
        sys.exit(f"unknown kind {kind}")

    registry = Registry()
    docs = {}
    for n in names:
        doc = load(os.path.join(d, n))
        docs[n] = doc
        res = Resource.from_contents(doc, default_specification=DRAFT7)
        registry = registry.with_resource(doc.get("$id", n), res)
        # CycloneDX refers to siblings by bare file name relative to its $id.
        if "$id" in doc:
            base = doc["$id"].rsplit("/", 1)[0] + "/"
            registry = registry.with_resource(base + n, res)

    schema = docs[main_name]
    cls = jsonschema.validators.validator_for(schema)
    cls = jsonschema.validators.extend(cls, {"pattern": _pattern})
    # The "regex" format (used when checking the schema itself) must also
    # understand \p{..}, so it is checked with the regex module too.
    fc = jsonschema.FormatChecker(list(cls.FORMAT_CHECKER.checkers))
    fc.checks("regex", raises=regex.error)(_is_regex)
    meta = cls.META_SCHEMA
    meta_errs = list(jsonschema.validators.validator_for(meta)(meta, format_checker=fc).iter_errors(schema))
    if meta_errs:
        sys.exit(f"{main_name} is not a valid schema: {meta_errs[0].message}")
    v = cls(schema, registry=registry, format_checker=fc)

    failed = False
    for f in files:
        errs = sorted(v.iter_errors(load(f)), key=lambda e: list(e.absolute_path))
        for e in errs[:20]:
            failed = True
            print(f"{f}: {'/'.join(map(str, e.absolute_path))}: {e.message[:300]}")
        if not errs:
            print(f"{f}: valid against {main_name}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
