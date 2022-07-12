# Fortigate2EOS-ACL-converter
## Prereuisites:
1. We need the fortigate policy rules in the same folder as the script (Refer to "cleaned_FW_config.txt" for refernce)
2. We need the "service_mapping.json" file which contains the services to port number mappings.

## Steps to run the script
1. Clone the repository
```
git clone https://github.com/MonsieurNemesis/Fortigate2EOS-ACL-converter.git
```
2. Run using 
```
python3 acl_script.py
```
## Output
A text file is created containing the ACL rules, grouped according to the source and destination interfaces.




-----
## Post ACL generation steps
### You may notice that the ACL rules generated contains hostnames such as:
```
permit tcp host 120.20.255.120 host www.google.com eq 445
```
Now this can be resolved by looking at the fortigate config file and checking out the abstracted member names (ip address) and subnet mask for each such hostname.


For this, you can refer to the 'hostnames.xlx' file, which gives you an idea of how you need to prepare the hostnames before you run the substitution script.

Once ready, execute the following:
```
python3 hostname_substitute_append.py
```
And VIOLA!
Your ACL hostnames have been substituted successfully with each member ip and subnet.

