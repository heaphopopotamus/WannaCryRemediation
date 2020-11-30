#!/usr/bin/env python3
"""
Usage:
  wcry_scanner.py (--subnet=<subnet>) (--outfile=<outfile>)

Options:
  --subnet=<subnet>             Subnet to scan example: 192.168.0.0/24
  --outfile=<output file>       Absolute path to output file example: /home/user/rhosts.log
"""
import logging

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s', 
    level=logging.DEBUG, 
    handlers=[
        logging.FileHandler(filename="wcry_scanner.log", mode="w+"),
        logging.StreamHandler()
        ]
    )

import os
import docopt
import masscan
import nmap

from datetime import datetime


def gather_cli_options() -> dict:
    """
    Return a dictionary with our docopt command line options.

    Args:
        None

    Returns:
        A dictionary containing the values provided by docopt via command line arguments
    """
    logging.info("Entering gather_cli_options")
    opts = docopt.docopt(__doc__)
    subnet = opts['--subnet']
    outfile = opts['--outfile']
    logging.info("CLI options gathered: {}".format(opts))
    return {"subnet": subnet, "outfile": outfile}


def run_masscan(subnet: str) -> list:
    """
    Run masscan against a subnet to quickly return a list of IPs with open port 445.

    Args:
        subnet: A subnet to scan

    Returns:
        A list of IPv4 addresses that report TCP port 445 as open by masscan

    Note:
        Masscan command: masscan -oX - <subnet> -p 445
    """
    logging.info("Entering run_masscan")
    rhosts_open_445 = []

    try:
        my_scanner = masscan.PortScanner()
    except masscan.PortScannerError as ex:
        logging.debug("MASSCAN not installed to OS path: {}".format(str(ex)))
        os._exit(1)
    
    logging.info("Begin masscan against subnet: {}".format(subnet))
    try:
        my_scanner.scan(subnet, ports='445')
        scan_results = my_scanner.scan_result['scan']
    except masscan.PortScannerError as ex:
        logging.debug("The masscan requires root privleges, run with sudo")
        os._exit(1)
    except KeyError as ex:
        logging.debug("Masscan results do not contain scan data: {}".format(str(ex)))
        os._exit(1)

    for host in my_scanner.all_hosts:
        try:
            if scan_results[host]['tcp'][445]['state'] == 'open':
                rhosts_open_445.append(host)
        except KeyError as ex:
            logging.debug("Port 445 closed on: {}".format(host))
            pass

    logging.debug("Hosts with open 445: {}".format(rhosts_open_445))
    return rhosts_open_445


def run_nmap(rhosts_open_445: list) -> list:
    """
    Nmap scan against returned list of IPs from masscan.

    Args:
        rhosts_open_445: List of hosts with TCP port 445 open

    Returns:
        A list of IPv4 addresses that report TCP port 445 as vulnerable to eternalblue by nmap

    Note:
        Nmap command: nmap -p445 --script smb-vuln-ms17-010 <target>
    """
    logging.info("Entering run_nmap")
    rhosts_ms17_vuln = []
    rhosts_list_str = ' '.join(rhosts_open_445)
    
    try:
        logging.info("Setting up nmap scanner")
        my_scanner = nmap.PortScanner()
    except nmap.nmap.PortScannerError as ex:
        logging.debug("NMAP not installed to OS path: {}".format(str(ex)))
        os._exit(1)
    
    try:
        logging.info("Begin nmap scan against IP list: {}".format(rhosts_open_445))
        full_results = my_scanner.scan(hosts=rhosts_list_str, arguments='-Pn -p445 --script smb-vuln-ms17-010')
        scan_results = full_results['scan']
    except nmap.nmap.PortScannerError as ex:
        logging.debug("The nmap scan requires root privleges, run with sudo")
        os._exit(1)
    except KeyError as ex:
        logging.debug("Results do not contain scan data: {}".format(str(ex)))
        os._exit(1)

    for host in my_scanner.all_hosts():
        try:
            if 'State: VULNERABLE' in scan_results[host]['hostscript'][0]['output']:
                logging.info("Host vulnerable: {}".format(host))
                rhosts_ms17_vuln.append(host)
        except:
            # Should we save not vuln to a seperate file?
            logging.info("Host not vulnerable: {}".format(host))
            pass
    return rhosts_ms17_vuln


def results_to_file(data: list, outfile: str) -> str:
    """
    Write the results to a file.

        Args:
            data: The data to write to the outfile
            outfile: The absolute path for the outfile of results

        Returns:
            The absolute path where the outfile is written containing all vulnerable IPs
    """
    logging.info("Entering results_to_file")
    logging.debug("Creating new outfile {}".format(outfile))
    with open(outfile, "w+") as file:
        for ip in data:
            file.write("{}\n".format(ip))
        file.close()
    logging.info("Results file: {}".format(outfile))
    return outfile


def main():
    """
    Main function to run script.
    """
    startTime = datetime.now()
    logging.info("Running wcry_scanner")
    cli_options = gather_cli_options()
    rhosts_open_445 = run_masscan(cli_options['subnet'])
    rhosts_ms17_vuln = run_nmap(rhosts_open_445)
    results_to_file(rhosts_ms17_vuln, cli_options['outfile'])
    logging.info("Completion time: {}".format(datetime.now() - startTime))


if __name__ == "__main__":
    main()
