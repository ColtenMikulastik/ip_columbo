
from termcolor import colored
import requests
import json
import time
import socket
import os


def printing_data(json_data, user_configs):
    """ print the data from the API request """

    # going to need to be refactored "cyclomatic complexity"
    # print info from api call
    # start by printing ip information
    print("ip information: ", end="")
    if user_configs["show"]["ipAddress"]:
        print(json_data["data"]["ipAddress"] + ", ", end="")
    if user_configs["show"]["isPublic"]:
        if json_data["data"]["isPublic"]:
            print("Public, ", end="")
        else:
            print("Private, ", end="")
    if user_configs["show"]["ipVersion"]:
        print("v" + str(json_data["data"]["ipVersion"]) + ", ", end="")
    if user_configs["show"]["isWhitelisted"]:
        if json_data["data"]["isWhitelisted"]:
            print("Whitelisted, ", end="")
        else:
            print("Not Whitelisted, ", end="")
    if user_configs["show"]["usageType"]:
        if json_data["data"]["usageType"] is None:
            print("Unknown Usage Type", end="")
        else:
            print(json_data["data"]["usageType"] + ", ", end="")
    if user_configs["show"]["isp"]:
        print("ISP: " + str(json_data["data"]["isp"]) + ", ", end="")
    if user_configs["show"]["isTor"]:
        if json_data["data"]["isTor"]:
            print("Using Tor, ", end="")
        else:
            pass
    print()

    if user_configs["show"]["abuseConfidenceScore"]:
        # print the abuse certainty graphically
        # 54 characters wide
        print("abuse certainty score: ", end="")
        score = json_data["data"]["abuseConfidenceScore"]
        if int(score) >= 50:
            char_color = "red"
        else:
            char_color = "green"
        zfill_score = str(score).zfill(3)
        score = int(round(score * .25))
        print('[', end="")
        for i in range(0, score):
            print(colored('=', color=char_color), end="")
        for i in range(score, 25):
            print(colored(' ', color=char_color), end="")
        print(']' + colored(zfill_score + '%', color=char_color))

    # print information about reports
    print("report data: ", end="")
    if user_configs["show"]["totalReports"]:
        print(str(json_data["data"]["totalReports"]) + " Reports, ", end="")
    if user_configs["show"]["lastReportedAt"]:
        print(
            "last report time:"
            + str(json_data["data"]["lastReportedAt"]) + ", ", end="")
    print()


def clean():
    """ clear the screen for all types of computers """
    # source "codingninjas.com"
    # For Windows
    if os.name == 'nt':
        _ = os.system('cls')

    # For macOS and Linux
    else:
        _ = os.system('clear')


def load_user_config():
    """ loads user configuration json file into dictionary """

    # gonna let the json error checking take care of itself
    with open("user_config.json", 'r') as conf_file:
        user_configs = json.load(conf_file)

    return user_configs


def abuseIPDB_API_Call(ip_address, user_configs):
    """ uses abuseIPDB_API_Call gets JSON """
    # unpack my api key
    # might require fix later
    with open(user_configs["api_keys"]["ipabusedb"], 'r') as file:
        key = file.read()
        key = key.split()
        key = "".join(key)

    # set parameters for the API request
    params = {
        "ipAddress": ip_address
    }
    headers = {
        "Key": key,
        "Accept": "application/json"
    }

    # call api
    api_response = requests.get("https://api.abuseipdb.com/api/v2/check",
                                params=params,
                                headers=headers)

    # format from byte thing to json dict
    json_resp = json.loads(api_response.content.decode("utf-8"))

    # print the info if request was good
    if api_response.status_code == 200:
        printing_data(json_resp, user_configs)
    else:
        # print error message
        print("api call fail")
        print("abuseipdb api response: " + json_resp["errors"][0]["detail"])


def main():
    """ gets user input and calls all the other functions """

    print("loading user configurations...")
    user_configs = load_user_config()
    print("configurations loaded successfully")
    time.sleep(.5)

    loop_prompt = True
    while loop_prompt:
        # print the splash art
        with open("banner.txt", 'r') as banner:
            print(banner.read())

        print("- enter 'q' to quit")

        ip_address = input("ip: ")
        # verify that the inputed data is correct using socket

        try:
            socket.inet_aton(ip_address)
            # continue to API call if ip is valid
            print("ip address detected...")
            abuseIPDB_API_Call(ip_address, user_configs)
        except socket.error:
            # not ip address, soooo other thing
            if ip_address == 'q':
                print("closing program")
                loop_prompt = False
                # break


if __name__ == "__main__":
    main()
