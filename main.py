from InquirerLib import prompt
from InquirerLib.InquirerPy.utils import InquirerPyKeybindings
from InquirerLib.InquirerPy.base import Choice
from colorama import Style, Fore

from utils import *
import services


prompt_key_bindings: InquirerPyKeybindings = {
    "toggle-all-true": [{"key": "a"}],
    "toggle-all-false": [{"key": "A"}],
    "toggle-all": [{"key": "i"}],
}


def ask_services_to_enable(bp):
    cli_questions = [
        {
            "type": "checkbox",
            "message": "Select AWS Services to inspect.",
            "name": "services",
            "choices": [
                Choice(service_name, enabled=bool(v["enabled"]))
                for service_name, v in bp.items()
            ],
        }
    ]

    answers = prompt(questions=cli_questions, keybindings=prompt_key_bindings)
    for service in bp.keys():
        bp[service]["enabled"] = service in answers["services"]
    return bp


def perform_bp_rules_check(bp):
    for service_name, service in bp.items():
        if not service["enabled"]:
            continue
        if service_name == "Lambda":
            service_name = "_lambda"

        module = getattr(services, convert_snake_case(service_name))
        for rule_name, rule in service["rules"].items():
            if not rule["enabled"]:
                continue

            rule["result"] = getattr(module, convert_snake_case(rule_name))()
    return bp


def show_bp_result(bp):
    for service_name, service in bp.items():
        if not service["enabled"]:
            continue
        print(f"{'=' * 25} {service_name + ' ':=<30}")

        for rule_name, rule in service["rules"].items():
            if not rule["enabled"]:
                continue

            if rule["result"].passed:
                style = Style.DIM
                color = Fore.GREEN
                mark = "✅"
            elif rule["level"] == 2 and not rule["result"].passed:
                style = Style.BRIGHT
                color = Fore.RED
                mark = "❌"
            elif rule["level"] == 1 and not rule["result"].passed:
                style = Style.NORMAL
                color = Fore.LIGHTRED_EX
                mark = "❕"

            print(f"{style}{rule_name:50}{Style.RESET_ALL} - {color}{mark}{Fore.RESET}")
            for resource in rule["result"].non_compliant_resources:
                print(f"    - {color}{resource}{Fore.RESET}")
        print()


if __name__ == "__main__":
    bp = load_bp_from_file()
    bp = ask_services_to_enable(bp)
    save_bp_to_file(bp)

    bp = perform_bp_rules_check(bp)
    show_bp_result(bp)
