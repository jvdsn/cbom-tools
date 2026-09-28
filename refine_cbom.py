import argparse
import json
import os
import sys

from google import genai
from google.genai import types
from pydantic import BaseModel


PROMPT = """For each algorithm component listed above, decide whether the Security Target
claims that the TOE uses that algorithm.

Rules:
- Base every decision only on the Security Target. Do not use outside knowledge about the product.
- Set keep=true only if the ST explicitly claims the algorithm.
- Where the CBOM component specifies a mode, key size, curve, or parameter set, the ST claim
  must match it. A claim for AES-256-GCM does not support keeping AES-128-CBC.
- For st_evidence, give the SFR identifier or section and a short quote supporting the decision.
  If keep=false, briefly state what you looked for and did not find.
- Return exactly one decision per bom_ref, copying each bom_ref value exactly as given."""


class Decision(BaseModel):
    bom_ref: str
    keep: bool
    st_evidence: str


class Decisions(BaseModel):
    decisions: list[Decision]


def filter_components(components, decided):
    filtered_components = []
    for component in components:
        if component["type"] != "cryptographic-asset" or component["cryptoProperties"].get("assetType") != "algorithm":
            filtered_components.append(component)
            continue

        bom_ref = component["bom-ref"]
        name = component["name"]
        if bom_ref not in decided:
            sys.exit(f"Model did not return decision for {bom_ref}")
        decision = decided[bom_ref]
        if decision.keep:
            print(f"Keeping {name}: {decision.st_evidence}")
            filtered_components.append(component)
        else:
            print(f"Removing {name}: {decision.st_evidence}")
    return filtered_components


def filter_dependencies(dependencies, decided):
    filtered_dependencies = []
    for dependency in dependencies:
        bom_ref = dependency["ref"]
        if "dependsOn" in dependency:
            dependency["dependsOn"] = [br for br in dependency["dependsOn"] if br not in decided or decided[br].keep]
        if "provides" in dependency:
            dependency["provides"] = [br for br in dependency["provides"] if br not in decided or decided[br].keep]
        if bom_ref not in decided or decided[bom_ref].keep:
            filtered_dependencies.append(dependency)
    return filtered_dependencies


def main():
    parser = argparse.ArgumentParser(description="Refine a CycloneDX 1.7 CBOM using a NIAP Security Target")
    parser.add_argument("-c", "--cbom", required=True)
    parser.add_argument("-s", "--st", required=True)
    parser.add_argument("-m", "--model", type=str, default="gemini-flash-latest")
    args = parser.parse_args()

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        sys.exit("Gemini API key must be set as environment variable GEMINI_API_KEY")

    if not os.path.isfile(args.cbom):
        sys.exit("CBOM does not exist")

    if not os.path.isfile(args.st):
        sys.exit("ST does not exist")

    with open(args.cbom, "r") as f:
        try:
            bom = json.load(f)
        except ValueError:
            sys.exit("CBOM is not valid JSON")

    candidates = []
    for component in bom["components"]:
        if component["type"] != "cryptographic-asset" or component["cryptoProperties"].get("assetType") != "algorithm":
            continue
        candidates.append({"bom-ref": component["bom-ref"], "name": component["name"], "cryptoProperties": component["cryptoProperties"]})

    if len(candidates) == 0:
        return

    client = genai.Client(api_key=api_key)
    uploaded_st = client.files.upload(file=args.st)
    try:
        response = client.models.generate_content(
            model=args.model,
            contents=[
                "Security Target:",
                uploaded_st,
                "Algorithm components from a CycloneDX 1.7 CBOM:\n" + json.dumps(candidates),
                PROMPT,
            ],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=Decisions,
            ),
        )
    finally:
        client.files.delete(name=uploaded_st.name)
        client.close()

    result = response.parsed
    if result is None:
        reason = response.candidates[0].finish_reason if response.candidates else "no candidates"
        sys.exit(f"Model returned no parseable output (finish_reason: {reason})")

    decided = {d.bom_ref: d for d in result.decisions}
    bom["components"] = filter_components(bom["components"], decided)

    if "dependencies" in bom:
        bom["dependencies"] = filter_dependencies(bom["dependencies"], decided)

    out_dir, base = os.path.split(args.cbom)
    with open(os.path.join(out_dir, f"refined-{base}"), "w") as f:
        json.dump(bom, f, indent=4)

if __name__ == "__main__":
    main()
