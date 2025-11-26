import os
import sys
import subprocess
from config import get_config
from utils.error_handler import get_error_handler, log_info, log_warning, handle_errors, NetSweepError

def banner():
    """Display the application banner"""
    print(r"""
            _                                         	
           | |                                        	
 _ __   ___| |_   ___  ___ __ _ _ __  _ __   ___ _ __ 
| '_ \ / _ \ __| / __|/ __/ _` | '_ \| '_ \ / _ \ '__|
| | | |  __/ |_  \__ \ (_| (_| | | | | | | |  __/ |   
|_| |_|\___|\__| |___/\___\__,_|_| |_|_| |_|\___|_|   
                                                                                                      
    """)
    print("Developed by: sondt\n")

def build_args_common():
    """Build common arguments based on user input and configuration"""
    config = get_config()
    handler = get_error_handler()

    args = []

    # Threads
    threads_input = input(f"Set threads (default {config.scan.max_workers}, Enter to skip): ")
    if threads_input:
        try:
            threads = int(threads_input)
            if threads > 0:
                args.extend(["-t", str(threads)])
            else:
                log_warning("Thread count must be positive, using default")
        except ValueError:
            log_warning("Invalid thread count, using default")
    else:
        args.extend(["-t", str(config.scan.max_workers)])

    # Timeout
    timeout_input = input(f"Set timeout (default {config.scan.timeout}s, Enter to skip): ")
    if timeout_input:
        try:
            timeout = float(timeout_input)
            if timeout > 0:
                args.extend(["-T", str(timeout)])
            else:
                log_warning("Timeout must be positive, using default")
        except ValueError:
            log_warning("Invalid timeout value, using default")
    else:
        args.extend(["-T", str(config.scan.timeout)])

    # Output format
    output_input = input(f"Export format? (json/csv/txt, default {config.output.export_format}, Enter to skip): ").lower()
    if output_input in ["json", "csv", "txt"]:
        args.extend(["-o", output_input])
    elif output_input == "":
        args.extend(["-o", config.output.export_format])
    else:
        log_warning("Invalid output format, using default")
        args.extend(["-o", config.output.export_format])

    # Output directory
    output_dir_input = input(f"Output directory (default {config.output.default_output_dir}, Enter to skip): ")
    if output_dir_input:
        args.extend(["-d", output_dir_input])
    else:
        args.extend(["-d", config.output.default_output_dir])

    # Verbose output
    verbose_input = input(f"Enable verbose output? (y/n, default {'y' if config.output.verbose else 'n'}): ").lower()
    if verbose_input == "y":
        args.append("-v")
    elif verbose_input == "n":
        pass  # Don't add -v flag
    elif verbose_input == "" and config.output.verbose:
        args.append("-v")

    return " ".join(args)


@handle_errors(default_return=None, reraise=True)
def execute_scanner(scanner_type: str, cmd: list) -> None:
    """Safely execute scanner with error handling

    Args:
        scanner_type: Type of scanner ('lan' or 'host')
        cmd: Command to execute
    """
    log_info(f"Executing {scanner_type} scanner: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=False, text=True)
        log_info(f"{scanner_type.capitalize()} scanner completed successfully")
        return result
    except subprocess.CalledProcessError as e:
        handler = get_error_handler()
        handler.log_error(f"{scanner_type.capitalize()} scanner failed with exit code {e.returncode}")
        if e.stdout:
            handler.log_error(f"Scanner output: {e.stdout}")
        if e.stderr:
            handler.log_error(f"Scanner errors: {e.stderr}")
        raise
    except FileNotFoundError:
        raise FileNotFoundError(f"Scanner script not found: {cmd[1]}")


@handle_errors(default_return=None, reraise=False)
def main():
    """Main application entry point with professional error handling"""
    # Initialize error handler and configuration
    config = get_config()
    handler = get_error_handler()

    log_info("NetSweep - Professional Network Scanner")
    log_info("Configuration loaded successfully")

    banner()

    while True:
        try:
            print("=== NetSweep Main Menu ===")
            print("1. Scan Local Network - Discover all active hosts (local)")
            print("2. Host Scanner - Scan specific hosts (local & remote)")
            print("3. Configuration - View and modify settings")
            print("0. Exit")

            choice = input("Your choice: ").strip()

            if choice == "1":
                log_info("User selected LAN Scanner")
                try:
                    args = build_args_common()
                    cmd = [sys.executable, "lan_scanner.py"] + args.split()
                    print(f"Running: {' '.join(cmd)}")
                    execute_scanner("lan", cmd)
                except Exception as e:
                    handler.handle_error(e, "LAN Scanner execution")
                    print(f"Error running LAN scanner. Check logs for details.")

            elif choice == "2":
                log_info("User selected Host Scanner")
                try:
                    target = input("Enter target (IP or domain): ").strip()
                    if not target:
                        print("Error: Target is required")
                        continue

                    ports_input = input(f"Enter port range (default {config.network.default_ports}): ").strip()
                    ports = ports_input or config.network.default_ports

                    cmd = [sys.executable, "host_scanner.py", "-t", target, "-p", ports]

                    # Add optional features
                    if input("Enable verbose output? (y/n): ").lower() == "y":
                        cmd.append("-v")
                    if input("Enable OS detection? (y/n): ").lower() == "y":
                        cmd.append("--os-detection")
                    if input("Enable Service detection? (y/n): ").lower() == "y":
                        cmd.append("--service-detection")

                    print(f"Running: {' '.join(cmd)}")
                    execute_scanner("host", cmd)
                except Exception as e:
                    handler.handle_error(e, "Host Scanner execution")
                    print(f"Error running host scanner. Check logs for details.")

            elif choice == "3":
                log_info("User selected Configuration")
                try:
                    show_configuration_menu(config, handler)
                except Exception as e:
                    handler.handle_error(e, "Configuration menu")
                    print("Error in configuration menu. Check logs for details.")

            elif choice == "0":
                log_info("User requested exit")
                print("Goodbye!")
                # Show error summary if there were any errors
                summary = handler.get_error_summary()
                if summary['total_errors'] > 0:
                    print(f"\nSession Summary: {summary['total_errors']} errors encountered")
                    print("Check logs for detailed information.")
                break

            else:
                print("Invalid choice! Please select again.")

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            log_info("User interrupted with Ctrl+C")
            break
        except Exception as e:
            handler.handle_error(e, "Main menu loop")
            print("An unexpected error occurred. Check logs for details.")


def show_configuration_menu(config, handler):
    """Display configuration menu options

    Args:
        config: Current configuration instance
        handler: Error handler instance
    """
    while True:
        print("\n=== Configuration Menu ===")
        print("1. View current configuration")
        print("2. Show error summary")
        print("3. Reset configuration to defaults")
        print("0. Back to main menu")

        choice = input("Your choice: ").strip()

        if choice == "1":
            print("\nCurrent Configuration:")
            print(f"  - Scan timeout: {config.scan.timeout}s")
            print(f"  - Max workers: {config.scan.max_workers}")
            print(f"  - Default port range: {config.network.default_ports}")
            print(f"  - Output format: {config.output.export_format}")
            print(f"  - Verbose output: {config.output.verbose}")
            print(f"  - Output directory: {config.output.default_output_dir}")

        elif choice == "2":
            summary = handler.get_error_summary()
            print(f"\nError Summary:")
            print(f"  - Total errors: {summary['total_errors']}")
            if summary['error_types']:
                print("  - Error types:")
                for error_type, count in summary['error_types'].items():
                    print(f"    * {error_type}: {count}")

        elif choice == "3":
            if input("Reset configuration to defaults? (y/n): ").lower() == "y":
                config.reset_to_defaults()
                log_info("Configuration reset to defaults")
                print("Configuration reset to defaults.")

        elif choice == "0":
            break

        else:
            print("Invalid choice! Please select again.")


if __name__ == "__main__":
    main()
