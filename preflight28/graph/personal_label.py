"""Set the single launcher resource selected by the pinned Bare 2.0.4 manifest."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from xml.etree import ElementTree


ANDROID = Path("chrome/android")
BASE_VALUES = ANDROID / "java/res_chromium_base/values"
LABEL = BASE_VALUES / "bare_launcher_label.xml"
UPSTREAM_SHA = "0510766ab72aedd7ca1c4d5208b70741ff76e3bb7c782ddd32d31c9de0f006ee"
PERSONAL_SHA = "e97675848cc5cb05e95ba9fa826948c304eeadffccd6147ce0a7912d2863ab65"
PERSONAL_ARGS_SHA = "ff20b56f6229e610e0d83f901a75ebce46d030e047f5a0e65295bdc577e25027"
MANIFEST_LABEL = 'android:label="{% block application_label %}@string/bare_launcher_label{% endblock %}"'


def prepare(src, *, apply):
    """Validate both identities and the normal build configuration before any write."""
    args = (src / "out/Bare/args.gn").read_bytes()
    if hashlib.sha256(args).hexdigest() != PERSONAL_ARGS_SHA:
        raise ValueError("Expected the pinned normal Personal 2.0.4 build arguments")
    manifest = (src / ANDROID / "java/AndroidManifest.xml").read_text()
    application = re.search(r"<application\s[^>]*>", manifest, re.DOTALL)
    if not application or application.group().count(MANIFEST_LABEL) != 1:
        raise ValueError("The application no longer selects the pinned launcher label")
    strings = ElementTree.parse(src / BASE_VALUES / "channel_constants.xml")
    names = strings.findall('./string[@name="app_name"]')
    if len(names) != 1 or names[0].text != "Bare Personal" or names[0].get("translatable") != "false":
        raise ValueError("The existing Personal app name is absent or ambiguous")
    resource = src / LABEL
    contents = resource.read_bytes()
    before = hashlib.sha256(contents).hexdigest()
    if before == PERSONAL_SHA:
        return {"path": str(LABEL), "before": before, "after": before}
    if not apply or before != UPSTREAM_SHA:
        raise ValueError("Unexpected contents of the separate launcher resource")
    updated = contents.replace(b">Bare</string>", b">Bare Personal</string>")
    after = hashlib.sha256(updated).hexdigest()
    if after != PERSONAL_SHA:
        raise ValueError("Unexpected replacement bytes for the Personal launcher")
    resource.write_bytes(updated)
    return {"path": str(LABEL), "before": before, "after": after}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("apply", "check"))
    parser.add_argument("--chromium-src", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.chromium_src, apply=args.operation == "apply"), sort_keys=True))


if __name__ == "__main__":
    main()
