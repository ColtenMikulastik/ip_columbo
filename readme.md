
# ip_columbo
This program is created to allow security analysts to quickly and effectively search for information on IP addresses.

## Configuring ip_columbo:
Edit the "user_config.json" file to add or remove output about specific ip's, dont forget to add the path to your api keys.


## Quick Start Steps

### Create account on [abusedipdb.com](https://www.abuseipdb.com/) 
- create an account and copy API key

### Clone this Repository locally
``` git clone https://github.com/ColtenMikulastik/ip_columbo.git ```

### Paste API Key into repository
- make sure to remember the file name of your api key

### Edit User Confiurations
- make edits in the "user_config.json" file,
    - "show" defines what will be shown when you search an ip
    - "api_keys" defines where each specific api key is locally



## Requirements:

### APIs
ip_columbo is heavily relyant on API keys to these websites.
- ***AbuseIPDB***
- ***VirusTotal*** (coming soon)

### ETC.
- Python3
    - requests
    - json

## Features / Improvements / Bug-Fixes
***DO NOT PUSH PERSONAL API KEYS TO GIT REPO***
#### Standard github procedures:
1. fork library to your own repos
2. make changes
3. make PR
