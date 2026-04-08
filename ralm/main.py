import argparse
import json
import hashlib
import os
import sys
import shutil
from datetime import datetime, UTC


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
RECEIPTS_DIR = "receipts"
FAILED_DIR = os.path.join(RECEIPTS_DIR, "failed")

RULE_REGISTRY = {
    "A1Z26": {
        "version": "1.0",
        "active": True,
        "directions": ["forward", "reverse"],
        "mode": "fail-closed",
        "description": "A=1 ... Z=26",
        "forward_min": 1,
        "forward_max": 26,
        "reverse_charset": ALPHABET,
    },
    "A0Z25": {
        "version": "1.0",
        "active": True,
        "directions": ["forward", "reverse"],
        "mode": "fail-closed",
        "description": "A=0 ... Z=25",
        "forward_min": 0,
        "forward_max": 25,
        "reverse_charset": ALPHABET,
    },
}


def map_a1z26_forward(values):
    output = []
    for v in values:
        if v < 1 or v > 26:
            raise ValueError(f"value out of range for A1Z26: {v}")
        output.append(ALPHABET[v - 1])
    return "".join(output)


def map_a1z26_reverse(text):
    values = []
    for ch in text:
        ch = ch.upper()
        if ch not in ALPHABET:
            raise ValueError(f"invalid character for A1Z26: {ch}")
        values.append(ALPHABET.index(ch) + 1)
    return values


def map_a0z25_forward(values):
    output = []
    for v in values:
        if v < 0 or v > 25:
            raise ValueError(f"value out of range for A0Z25: {v}")
        output.append(ALPHABET[v])
    return "".join(output)


def map_a0z25_reverse(text):
    values = []
    for ch in text:
        ch = ch.upper()
        if ch not in ALPHABET:
            raise ValueError(f"invalid character for A0Z25: {ch}")
        values.append(ALPHABET.index(ch))
    return values


def utc_now_iso():
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def utc_stamp():
    return datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")


def get_rule_spec(rule_name):
    rule = rule_name.upper()
    if rule not in RULE_REGISTRY:
        raise ValueError(f"unsupported rule: {rule}")
    return rule, RULE_REGISTRY[rule]


def build_receipt(
    input_data,
    rule,
    mode,
    direction,
    output,
    status,
    reproducibility,
    admissibility,
    admissibility_reason,
    rule_version,
):
    return {
        "tool": "RALM v0.4-dev",
        "observer": "HACR-ALL",
        "input": input_data,
        "rule": rule,
        "rule_version": rule_version,
        "mode": mode,
        "direction": direction,
        "output": output,
        "admissibility": admissibility,
        "admissibility_reason": admissibility_reason,
        "reproducibility": reproducibility,
        "status": status,
        "timestamp_utc": utc_now_iso(),
    }


def save_receipt(receipt):
    os.makedirs(RECEIPTS_DIR, exist_ok=True)
    payload = json.dumps(receipt, indent=2)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    receipt["sha256"] = digest
    final_payload = json.dumps(receipt, indent=2)

    filename = f"receipt_{utc_stamp()}.json"
    path = os.path.join(RECEIPTS_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        f.write(final_payload)

    return path, digest


def parse_numbers(input_text):
    parts = [p.strip() for p in input_text.split(",") if p.strip()]
    if not parts:
        raise ValueError("no input values provided")
    return [int(p) for p in parts]


def parse_text(input_text):
    text = input_text.strip().upper()
    if not text:
        raise ValueError("no input text provided")
    return text


def check_rule_admissibility(rule, mode, direction, input_data):
    rule_name, spec = get_rule_spec(rule)

    if not spec["active"]:
        return False, "rule inactive", spec["version"], rule_name

    if mode != spec["mode"]:
        return False, f"mode {mode} not allowed for {rule_name}", spec["version"], rule_name

    if direction not in spec["directions"]:
        return False, f"direction {direction} not allowed for {rule_name}", spec["version"], rule_name

    if direction == "forward":
        if not isinstance(input_data, list) or not input_data:
            return False, "forward input must be a non-empty integer list", spec["version"], rule_name
        for value in input_data:
            if not isinstance(value, int):
                return False, f"non-integer forward input: {value}", spec["version"], rule_name
            if value < spec["forward_min"] or value > spec["forward_max"]:
                return (
                    False,
                    f"input value {value} outside {rule_name} forward domain",
                    spec["version"],
                    rule_name,
                )
        return True, "rule active and input within declared domain", spec["version"], rule_name

    if direction == "reverse":
        if not isinstance(input_data, str) or not input_data:
            return False, "reverse input must be a non-empty string", spec["version"], rule_name
        for ch in input_data:
            if ch.upper() not in spec["reverse_charset"]:
                return (
                    False,
                    f"character {ch} outside {rule_name} reverse domain",
                    spec["version"],
                    rule_name,
                )
        return True, "rule active and input within declared domain", spec["version"], rule_name

    return False, f"invalid direction {direction}", spec["version"], rule_name


def recompute_output(input_data, rule, mode, direction):
    admitted, reason, _, rule_name = check_rule_admissibility(rule, mode, direction, input_data)
    if not admitted:
        raise ValueError(reason)

    if direction == "forward":
        if rule_name == "A1Z26":
            return map_a1z26_forward(input_data)
        if rule_name == "A0Z25":
            return map_a0z25_forward(input_data)

    if direction == "reverse":
        if rule_name == "A1Z26":
            return map_a1z26_reverse(input_data)
        if rule_name == "A0Z25":
            return map_a0z25_reverse(input_data)

    raise ValueError(f"invalid direction in receipt: {direction}")


def list_receipt_files():
    if not os.path.isdir(RECEIPTS_DIR):
        return []
    files = []
    for name in os.listdir(RECEIPTS_DIR):
        full_path = os.path.join(RECEIPTS_DIR, name)
        if os.path.isfile(full_path) and name.lower().startswith("receipt_") and name.lower().endswith(".json"):
            files.append(full_path)
    files.sort(key=os.path.getmtime)
    return files


def list_summary_files():
    if not os.path.isdir(RECEIPTS_DIR):
        return []
    files = []
    for name in os.listdir(RECEIPTS_DIR):
        full_path = os.path.join(RECEIPTS_DIR, name)
        if os.path.isfile(full_path) and name.lower().startswith("summary_") and name.lower().endswith(".json"):
            files.append(full_path)
    files.sort(key=os.path.getmtime)
    return files


def load_latest_receipt():
    files = list_receipt_files()
    if not files:
        raise FileNotFoundError("no receipt files found")
    return load_json_file(files[-1])


def load_latest_summary():
    files = list_summary_files()
    if not files:
        raise FileNotFoundError("no summary files found")
    return load_json_file(files[-1])


def load_receipt_file(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"receipt file not found: {path}")
    return load_json_file(path)


def load_summary_file(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"summary file not found: {path}")
    return load_json_file(path)


def load_json_file(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return path, data


def verify_receipt_file(path, receipt):
    stored_sha = receipt.get("sha256", "")
    receipt_copy = dict(receipt)
    receipt_copy.pop("sha256", None)

    payload = json.dumps(receipt_copy, indent=2)
    recomputed_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    sha_match = stored_sha == recomputed_sha

    try:
        admitted, reason, rule_version, rule_name = check_rule_admissibility(
            receipt.get("rule", ""),
            receipt.get("mode", ""),
            receipt.get("direction", "forward"),
            receipt.get("input"),
        )
        admissibility = "PASS" if admitted else "FAIL"
        admissibility_reason = reason
        version_match = receipt.get("rule_version", "") == rule_version
        expected_output = recompute_output(
            receipt.get("input"),
            rule_name,
            receipt.get("mode", ""),
            receipt.get("direction", "forward"),
        )
        output_match = expected_output == receipt.get("output")
        reproducibility = "PASS" if output_match else "FAIL"
    except Exception as e:
        expected_output = ""
        output_match = False
        reproducibility = "FAIL"
        admissibility = "FAIL"
        admissibility_reason = str(e)
        version_match = False

    integrity = "PASS" if sha_match else "FAIL"
    version_status = "PASS" if version_match else "FAIL"
    status = "PASS" if sha_match and output_match and admissibility == "PASS" and version_match else "FAIL"

    return {
        "path": path,
        "stored_sha256": stored_sha,
        "recomputed_sha256": recomputed_sha,
        "expected_output": expected_output,
        "recorded_output": receipt.get("output"),
        "reproducibility": reproducibility,
        "integrity": integrity,
        "admissibility": admissibility,
        "admissibility_reason": admissibility_reason,
        "rule_version_status": version_status,
        "status": status,
    }


def print_audit_result(result):
    print("RALM AUDIT")
    print(f"receipt: {result['path']}")
    print("observer: HACR-ALL")
    print(f"stored_sha256: {result['stored_sha256']}")
    print(f"recomputed_sha256: {result['recomputed_sha256']}")
    print(f"integrity: {result['integrity']}")
    print(f"admissibility: {result['admissibility']}")
    print(f"admissibility_reason: {result['admissibility_reason']}")
    print(f"rule_version_status: {result['rule_version_status']}")
    print(f"expected_output: {result['expected_output']}")
    print(f"recorded_output: {result['recorded_output']}")
    print(f"reproducibility: {result['reproducibility']}")
    print(f"status: {result['status']}")


def print_json(path, data, header):
    print(header)
    print(f"path: {path}")
    print(json.dumps(data, indent=2))


def run_registry(args):
    print("RALM RULE REGISTRY")
    print("observer: HACR-ALL")
    for rule_name, spec in RULE_REGISTRY.items():
        print(f"rule: {rule_name}")
        print(f"  version: {spec['version']}")
        print(f"  active: {spec['active']}")
        print(f"  directions: {', '.join(spec['directions'])}")
        print(f"  mode: {spec['mode']}")
        print(f"  description: {spec['description']}")
        print(f"  forward_domain: {spec['forward_min']}..{spec['forward_max']}")


def run_map(args):
    rule = args.rule.upper()
    mode = args.mode.lower()

    try:
        if args.direction == "forward":
            input_data = parse_numbers(args.input)
        else:
            input_data = parse_text(args.input)

        admitted, admissibility_reason, rule_version, rule_name = check_rule_admissibility(
            rule, mode, args.direction, input_data
        )

        if not admitted:
            raise ValueError(admissibility_reason)

        output = recompute_output(input_data, rule_name, mode, args.direction)
        rerun_output = recompute_output(input_data, rule_name, mode, args.direction)
        reproducibility = "PASS" if rerun_output == output else "FAIL"
        status = "PASS" if reproducibility == "PASS" and admitted else "FAIL"

        receipt = build_receipt(
            input_data=input_data,
            rule=rule_name,
            rule_version=rule_version,
            mode=mode,
            direction=args.direction,
            output=output,
            status=status,
            reproducibility=reproducibility,
            admissibility="PASS",
            admissibility_reason=admissibility_reason,
        )
        path, digest = save_receipt(receipt)

        print("RALM RECEIPT")
        print(f"direction: {args.direction}")
        print(f"input: {input_data}")
        print(f"rule: {rule_name}")
        print(f"rule_version: {rule_version}")
        print(f"mode: {mode}")
        print(f"output: {output}")
        print("observer: HACR-ALL")
        print("admissibility: PASS")
        print(f"admissibility_reason: {admissibility_reason}")
        print(f"reproducibility: {reproducibility}")
        print(f"status: {status}")
        print(f"receipt: {path}")
        print(f"sha256: {digest}")

    except Exception as e:
        failure_input = [] if args.direction == "forward" else ""
        failure_output = "" if args.direction == "forward" else []

        try:
            _, spec = get_rule_spec(rule)
            rule_version = spec["version"]
            rule_name = rule
        except Exception:
            rule_version = "unknown"
            rule_name = rule

        receipt = build_receipt(
            input_data=failure_input,
            rule=rule_name,
            rule_version=rule_version,
            mode=mode,
            direction=args.direction,
            output=failure_output,
            status="FAIL",
            reproducibility="FAIL",
            admissibility="FAIL",
            admissibility_reason=str(e),
        )
        path, digest = save_receipt(receipt)

        print("RALM RECEIPT")
        print(f"direction: {args.direction}")
        print(f"rule: {rule_name}")
        print(f"rule_version: {rule_version}")
        print(f"mode: {mode}")
        print("observer: HACR-ALL")
        print("admissibility: FAIL")
        print(f"admissibility_reason: {e}")
        print("status: FAIL")
        print(f"receipt: {path}")
        print(f"sha256: {digest}")
        sys.exit(1)


def run_audit(args):
    try:
        if args.last:
            path, receipt = load_latest_receipt()
            result = verify_receipt_file(path, receipt)
            print_audit_result(result)
            if result["status"] != "PASS":
                sys.exit(1)
            return

        if args.file:
            path, receipt = load_receipt_file(args.file)
            result = verify_receipt_file(path, receipt)
            print_audit_result(result)
            if result["status"] != "PASS":
                sys.exit(1)
            return

        if args.all:
            files = list_receipt_files()
            if not files:
                raise FileNotFoundError("no receipt files found")

            print("RALM AUDIT ALL")
            print("observer: HACR-ALL")
            print(f"count: {len(files)}")

            failed = 0
            for index, path in enumerate(files, start=1):
                _, receipt = load_receipt_file(path)
                result = verify_receipt_file(path, receipt)
                print(f"{index}. {path} -> {result['status']}")
                if result["status"] != "PASS":
                    failed += 1

            overall = "PASS" if failed == 0 else "FAIL"
            print(f"failed: {failed}")
            print(f"status: {overall}")

            if overall != "PASS":
                sys.exit(1)
            return

        raise ValueError("provide --last, --file, or --all")

    except Exception as e:
        print("RALM AUDIT")
        print("observer: HACR-ALL")
        print("status: FAIL")
        print(f"reason: {e}")
        sys.exit(1)


def run_list_receipts(args):
    files = list_receipt_files()

    print("RALM RECEIPTS")
    print("observer: HACR-ALL")

    if not files:
        print("count: 0")
        return

    print(f"count: {len(files)}")

    for index, path in enumerate(files, start=1):
        print(f"{index}. {path}")


def run_list_summaries(args):
    files = list_summary_files()

    print("RALM SUMMARIES")
    print("observer: HACR-ALL")

    if not files:
        print("count: 0")
        return

    print(f"count: {len(files)}")

    for index, path in enumerate(files, start=1):
        print(f"{index}. {path}")


def run_show(args):
    try:
        if args.last:
            path, receipt = load_latest_receipt()
            print_json(path, receipt, "RALM SHOW RECEIPT")
            return

        if args.file:
            path, receipt = load_receipt_file(args.file)
            print_json(path, receipt, "RALM SHOW RECEIPT")
            return

        raise ValueError("provide --last or --file")

    except Exception as e:
        print("RALM SHOW RECEIPT")
        print("observer: HACR-ALL")
        print("status: FAIL")
        print(f"reason: {e}")
        sys.exit(1)


def run_show_summary(args):
    try:
        if args.last:
            path, summary = load_latest_summary()
            print_json(path, summary, "RALM SHOW SUMMARY")
            return

        if args.file:
            path, summary = load_summary_file(args.file)
            print_json(path, summary, "RALM SHOW SUMMARY")
            return

        raise ValueError("provide --last or --file")

    except Exception as e:
        print("RALM SHOW SUMMARY")
        print("observer: HACR-ALL")
        print("status: FAIL")
        print(f"reason: {e}")
        sys.exit(1)


def run_export_summary(args):
    try:
        files = list_receipt_files()
        if not files:
            raise FileNotFoundError("no receipt files found")

        summary = {
            "tool": "RALM v0.4-dev",
            "observer": "HACR-ALL",
            "generated_at_utc": utc_now_iso(),
            "receipt_count": len(files),
            "failed_count": 0,
            "status": "PASS",
            "receipts": [],
        }

        for path in files:
            _, receipt = load_receipt_file(path)
            result = verify_receipt_file(path, receipt)

            entry = {
                "path": path,
                "timestamp_utc": receipt.get("timestamp_utc", ""),
                "input": receipt.get("input"),
                "rule": receipt.get("rule", ""),
                "rule_version": receipt.get("rule_version", ""),
                "mode": receipt.get("mode", ""),
                "direction": receipt.get("direction", "forward"),
                "output": receipt.get("output"),
                "admissibility": receipt.get("admissibility", ""),
                "admissibility_reason": receipt.get("admissibility_reason", ""),
                "stored_sha256": receipt.get("sha256", ""),
                "integrity": result["integrity"],
                "reproducibility": result["reproducibility"],
                "status": result["status"],
            }
            summary["receipts"].append(entry)

            if result["status"] != "PASS":
                summary["failed_count"] += 1

        summary["status"] = "PASS" if summary["failed_count"] == 0 else "FAIL"

        os.makedirs(RECEIPTS_DIR, exist_ok=True)
        filename = f"summary_{utc_stamp()}.json"
        path = os.path.join(RECEIPTS_DIR, filename)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print("RALM EXPORT SUMMARY")
        print("observer: HACR-ALL")
        print(f"summary: {path}")
        print(f"receipt_count: {summary['receipt_count']}")
        print(f"failed_count: {summary['failed_count']}")
        print(f"status: {summary['status']}")

        if summary["status"] != "PASS":
            sys.exit(1)

    except Exception as e:
        print("RALM EXPORT SUMMARY")
        print("observer: HACR-ALL")
        print("status: FAIL")
        print(f"reason: {e}")
        sys.exit(1)


def run_clean_failed(args):
    try:
        files = list_receipt_files()
        if not files:
            raise FileNotFoundError("no receipt files found")

        os.makedirs(FAILED_DIR, exist_ok=True)

        moved = 0
        for path in files:
            _, receipt = load_receipt_file(path)
            result = verify_receipt_file(path, receipt)
            if result["status"] != "PASS":
                destination = os.path.join(FAILED_DIR, os.path.basename(path))
                if os.path.exists(destination):
                    base, ext = os.path.splitext(os.path.basename(path))
                    destination = os.path.join(FAILED_DIR, f"{base}_{utc_stamp()}{ext}")
                shutil.move(path, destination)
                moved += 1
                print(f"MOVED: {path} -> {destination}")

        print("RALM CLEAN FAILED")
        print("observer: HACR-ALL")
        print(f"moved: {moved}")
        print("status: PASS")

    except Exception as e:
        print("RALM CLEAN FAILED")
        print("observer: HACR-ALL")
        print("status: FAIL")
        print(f"reason: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="RALM v0.4-dev")
    subparsers = parser.add_subparsers(dest="command", required=True)

    registry_parser = subparsers.add_parser("registry", help="show declared rules")
    registry_parser.set_defaults(func=run_registry)

    map_parser = subparsers.add_parser("map", help="map in forward or reverse direction")
    map_parser.add_argument("--rule", required=True, help="mapping rule: a1z26 or a0z25")
    map_parser.add_argument("--mode", required=True, help="execution mode, e.g. fail-closed")
    map_parser.add_argument("--direction", choices=["forward", "reverse"], required=True, help="mapping direction")
    map_parser.add_argument("--input", required=True, help='forward: "8,1,3,18" | reverse: "HACR"')
    map_parser.set_defaults(func=run_map)

    audit_parser = subparsers.add_parser("audit", help="audit receipts")
    audit_target = audit_parser.add_mutually_exclusive_group(required=True)
    audit_target.add_argument("--last", action="store_true", help="audit latest receipt")
    audit_target.add_argument("--file", help="audit a specific receipt file")
    audit_target.add_argument("--all", action="store_true", help="audit all receipt files")
    audit_parser.set_defaults(func=run_audit)

    list_receipts_parser = subparsers.add_parser("list-receipts", help="list receipt files")
    list_receipts_parser.set_defaults(func=run_list_receipts)

    list_summaries_parser = subparsers.add_parser("list-summaries", help="list summary files")
    list_summaries_parser.set_defaults(func=run_list_summaries)

    show_parser = subparsers.add_parser("show", help="show receipt contents")
    show_target = show_parser.add_mutually_exclusive_group(required=True)
    show_target.add_argument("--last", action="store_true", help="show latest receipt")
    show_target.add_argument("--file", help="show a specific receipt file")
    show_parser.set_defaults(func=run_show)

    show_summary_parser = subparsers.add_parser("show-summary", help="show summary contents")
    show_summary_target = show_summary_parser.add_mutually_exclusive_group(required=True)
    show_summary_target.add_argument("--last", action="store_true", help="show latest summary")
    show_summary_target.add_argument("--file", help="show a specific summary file")
    show_summary_parser.set_defaults(func=run_show_summary)

    export_parser = subparsers.add_parser("export-summary", help="export summary of all receipts")
    export_parser.set_defaults(func=run_export_summary)

    clean_parser = subparsers.add_parser("clean-failed", help="move failed receipts out of active set")
    clean_parser.set_defaults(func=run_clean_failed)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()