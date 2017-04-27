# Detect-machine-LAN Fork

# What is this
Detect LAN machine is a software written in python to detect machines that connect to your network using nmap and using whitelist, if you find a team that is not in the whitelist can send an email notice.

This fork is part of the exercises for UCLM ESII-2.

## Dependencies

- Python 3.x
- Requires [python-nmap library](https://bitbucket.org/xael/python-nmap).

## Using Detect-machine-LAN
To display the help run:
```
python3 DetectMachineLan.py --help
```

Example
```
python3 DetectMachineLan.py -w whitelist.txt -l detect.log -r 192.168.100.0/24 -v -u user@server.com --pwd=123456 -s server.com -p 587 --et=destination@server.com
```

## Changelog
### v0.2
- Added detection of duplicate MAC. 

### v0.1
- Script converted to Python 3.

- Adapted to PEP8 style guide.

- The log file path now is configurable with the -l paramter.

- Removed GTK features.
