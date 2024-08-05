import json
import shutil


def load_bp_from_file(filepath="bp.json"):
    try:
        with open(filepath, "r") as f:
            content = "".join(f.readlines())
    except FileNotFoundError:
        shutil.copy("bp-base.json", filepath)
        with open(filepath, "r") as f:
            content = "".join(f.readlines())

    return json.loads(content)


def save_bp_to_file(bp, filepath="bp.json"):
    with open(filepath, "w") as f:
        f.write(json.dumps(bp, indent=2))


def convert_snake_case(text):
    return text.lower().replace(" ", "_").replace("-", "_")


def convert_bp_to_snake_case(bp):
    bp = {
        service_name.lower().replace(" ", "_"): value
        for service_name, value in bp.items()
    }
    for v in bp.values():
        v["rules"] = {
            rule_name.lower().replace("-", "_"): rule
            for rule_name, rule in v["rules"].items()
        }
    return bp


if __name__ == "__main__":
    bp = load_bp_from_file()
    rules = [
        (
            k.lower().replace(" ", "_"),
            list(map(lambda x: x.replace("-", "_"), v["rules"].keys())),
        )
        for k, v in bp.items()
    ]
    print(json.dumps(rules, indent=2))
    for rule in rules:
        file_name = rule[0]
        rule_names = rule[1]
        file_template = f"""from models import RuleCheckResult
import boto3


# client = boto3.client("")
"""
        with open(f"services/{file_name}.py", "w") as f:
            f.write(file_template)
            for rule_name in rule_names:
                function_template = f"""

def {rule_name}():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
"""
                f.write(function_template)
