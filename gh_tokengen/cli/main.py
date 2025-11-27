import sys
from gh_tokengen.cli.args import parse_arguments, validate_command_line_args
from gh_tokengen.cli.inputs import collect_inputs
from gh_tokengen.cli.commands import generate_token, show_progress_and_debug_info
def main() -> None:
    """Main entry point - orchestrates token generation workflow."""
    args = parse_arguments()
    validate_command_line_args(args)
    client_id, pem_path, pem_path_str, installation_id = collect_inputs(args)
    show_progress_and_debug_info(args, client_id, pem_path_str, installation_id)
    generate_token(args, client_id, pem_path, installation_id)

