import argparse
import logging
import os
import subprocess
import sys
import json
import pkg_resources
from packaging import version

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Identifies potential dependency confusion attacks.")
    parser.add_argument(
        "-p",
        "--package",
        type=str,
        help="The name of the package to check (e.g., 'my_package'). If not provided, checks all installed packages.",
    )
    parser.add_argument(
        "-r",
        "--pypi_url",
        type=str,
        default="https://pypi.org/pypi/",
        help="The base URL of the PyPI repository (default: https://pypi.org/pypi/)."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output for debugging."
    )

    return parser.parse_args()


def check_package_availability(package_name, pypi_url):
    """
    Checks if a package exists on PyPI and returns the version if it does.

    Args:
        package_name (str): The name of the package to check.
        pypi_url (str): The base URL of the PyPI repository.

    Returns:
        str: The latest version of the package on PyPI, or None if not found.

    Raises:
        subprocess.CalledProcessError: If the `pip` command fails.
        Exception: For other errors during the process.
    """
    try:
        # Use pip to check for the package on PyPI
        command = [
            sys.executable,
            "-m",
            "pip",
            "index",
            "versions",
            package_name,
            "--index-url",
            pypi_url
        ]

        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Parse the output to extract versions. This approach is fragile
        # and should be improved with a dedicated API call if PyPI allows it.

        if result.stdout:
            for line in result.stdout.splitlines():
                if "Latest version" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        return parts[1].strip()
            return None
        else:
            logging.warning(f"Package '{package_name}' not found on PyPI.")
            return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Error checking package '{package_name}' on PyPI: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def get_installed_packages():
    """
    Gets a list of all installed packages and their versions.

    Returns:
        dict: A dictionary where keys are package names and values are their versions.
    """
    installed_packages = {}
    try:
        for package in pkg_resources.working_set:
            installed_packages[package.key] = package.version
    except Exception as e:
        logging.error(f"Error getting installed packages: {e}")
        return {}  # Return empty dictionary in case of error

    return installed_packages


def main():
    """
    Main function to execute the dependency confusion check.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.package:
        packages_to_check = {args.package: None}
    else:
        packages_to_check = get_installed_packages()

    if not packages_to_check:
        logging.warning("No packages found to check.")
        sys.exit(0)

    vulnerable_packages = []

    for package_name, installed_version in packages_to_check.items():
        try:
            pypi_version = check_package_availability(package_name, args.pypi_url)

            if pypi_version is None:
                # Package not found on PyPI - potential internal package
                logging.info(f"Package '{package_name}' not found on PyPI.")
            else:
                installed_version_obj = version.parse(installed_version) if installed_version else None
                pypi_version_obj = version.parse(pypi_version)

                if installed_version_obj is not None and installed_version_obj > pypi_version_obj:
                    logging.warning(
                        f"Potential Dependency Confusion: Locally installed version '{installed_version}'"
                        f" of '{package_name}' is newer than the PyPI version '{pypi_version}'."
                    )
                    vulnerable_packages.append({
                        "package": package_name,
                        "installed_version": installed_version,
                        "pypi_version": pypi_version
                    })
                else:
                    logging.info(f"Package '{package_name}' is up-to-date or older than PyPI version.")

        except subprocess.CalledProcessError:
            logging.error(f"Failed to check package '{package_name}'. Skipping...")
        except Exception as e:
            logging.error(f"An error occurred while processing '{package_name}': {e}")

    if vulnerable_packages:
        print("\nPotential Dependency Confusion Vulnerabilities Found:")
        for vuln in vulnerable_packages:
            print(
                f"  - Package: {vuln['package']}, Installed Version: {vuln['installed_version']},"
                f" PyPI Version: {vuln['pypi_version']}"
            )
        sys.exit(1)  # Exit with error code if vulnerabilities are found
    else:
        print("No potential dependency confusion vulnerabilities found.")
        sys.exit(0)


if __name__ == "__main__":
    # Example Usage 1: Check all installed packages
    # python main.py

    # Example Usage 2: Check a specific package
    # python main.py -p my_package

    # Example Usage 3: Check a specific package with a custom PyPI URL
    # python main.py -p my_package -r https://my-custom-pypi.example.com/simple

    # Example Usage 4: Enable verbose logging
    # python main.py -v

    # Example Usage 5: Check a non-existent package on PyPI
    # python main.py -p non_existent_package

    main()