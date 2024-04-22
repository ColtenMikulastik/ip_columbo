
# ip_columbo
This program is created to allow security analysts to quickly and effectively search for information on IP addresses.

## Configuring ip_columbo:
Edit the "user_config.json" file to add or remove output about specific ip's, dont forget to add the path to your api keys.


## Quick Start Steps

### Create account on [abusedipdb.com](https://www.abuseipdb.com/) 
- create an account and copy your API key

### Clone this Repository locally
``` git clone https://github.com/ColtenMikulastik/ip_columbo.git ```

### Paste API Key into repository
- make sure to remember the file name of your api key

### Edit User Confiurations
- make edits in the "user_config.json" file,
    - "show" defines what will be shown when you search an ip
        - edit these with "*true*" or "*false*" depending.
    - "api_keys" defines where each key is in your local files
        - edit thes to point to the correct file:
            - ex: ``` "ipabusedb": "myapikey.key" ```

### Run the Requirements script
- depending on your environment:
    1. you might have to create a virtual environment using:
        - ``` python3 -m venv ./venv ```
        - and then using your virtual environment to install the requirements:
        - ``` ./venv/bin/pip3 install -r requirements.txt ```
    
    2. or you might already be in a virtual environment where you might have to run:
        - ``` pip3 install -r requirements.txt ```
        - or manage the dependencies in your package manager

### (Done) Run the program
- your ready to go!
    - using ``` ./venv/bin/python3 . ``` or using your IDE start the program


## Requirements:

### APIs
ip_columbo is heavily relyant on API keys to these websites.
- ***AbuseIPDB***
- ***ip-api.com*** (doesn't require key)
- ***malware bazaar***

### ETC.
- Python3
    - requests
    - json

## Workflow
just copy and paste the concerning ip address, domain name, or hash into the search.
- Ip columbo will automattically search for the relevant information.
- new feature, if you have determined the ip address to be malicous you can now automattically report through ip_columbo

## Features / Improvements / Bug-Fixes
***DO NOT PUSH PERSONAL API KEYS TO GIT REPO***
#### Standard github procedures:
1. fork library to your own repos
2. make branch for your code
3. make changes
3. make PR to my repo on your changes branch
