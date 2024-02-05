
from termcolor import colored
import requests
import json
import time
import socket
import os


def print_geolocation_info(json_data, user_configs):
    """ prints info about from ip geoloc api call """

    # prints header, and then indents each of the values
    print("geolocation api results:")
    for key, value in json_data.items():
        if user_configs["show"]["ipgeoloc"][key]:
            print("\t" + str(key) + ": " + str(value))
    print("")


def print_ip_information(json_data, user_configs):
    """ prints the ip information from api """

    # print ip info based on the user configs
    print("ip information: ", end="")
    if user_configs["show"]["ipabusedb"]["ipAddress"]:
        print(json_data["data"]["ipAddress"] + ", ", end="")
    if user_configs["show"]["ipabusedb"]["isPublic"]:
        if json_data["data"]["isPublic"]:
            print("Public, ", end="")
        else:
            print("Private, ", end="")
    if user_configs["show"]["ipabusedb"]["ipVersion"]:
        print("v" + str(json_data["data"]["ipVersion"]) + ", ", end="")
    if user_configs["show"]["ipabusedb"]["isWhitelisted"]:
        if json_data["data"]["isWhitelisted"]:
            print("Whitelisted, ", end="")
        else:
            print("Not Whitelisted, ", end="")
    if user_configs["show"]["ipabusedb"]["usageType"]:
        if json_data["data"]["usageType"] is None:
            print("Unknown Usage Type", end="")
        else:
            print(json_data["data"]["usageType"] + ", ", end="")
    if user_configs["show"]["ipabusedb"]["isTor"]:
        if json_data["data"]["isTor"]:
            print("Using Tor, ", end="")
        else:
            pass
    print()


def print_domain_information(json_data, user_configs):
    """ prints dns isp and hostname infomration """

    # this will be right after the "print_ip_information" func
    if user_configs["show"]["ipabusedb"]["isp"]:
        print("\tISP: " + str(json_data["data"]["isp"]))
    if user_configs["show"]["ipabusedb"]["domain"]:
        print("\tDomain: " + str(json_data["data"]["domain"]))
    if user_configs["show"]["ipabusedb"]["hostnames"]:
        print("\tHostnames: ", end='')
        for hostname in json_data["data"]["hostnames"]:
            print(hostname + ", ")
    print('\n')


def print_abuse_conf_score(json_data, user_configs):
    """ prints abuse confidence score from api """

    # prints the value as a bar with cool percentage at the end
    if user_configs["show"]["ipabusedb"]["abuseConfidenceScore"]:
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


def print_report_data(json_data, user_configs):
    """ prints data about reports from the api """

    # general information about reports
    print("report data: ", end="")
    if user_configs["show"]["ipabusedb"]["totalReports"]:
        print(str(json_data["data"]["totalReports"]) + " Reports in the last month, ", end="")
    if user_configs["show"]["ipabusedb"]["lastReportedAt"]:
        print(
            "last report time:"
            + str(json_data["data"]["lastReportedAt"]) + ", ", end="")
    print("")

    # print the verbose specific reports
    if user_configs["show"]["ipabusedb"]["verboseReports"]:
        user_def_max_report = user_configs["show"]["ipabusedb"]["reportNumber"]
        # loop through reports until max report ammount of last index is hit
        for report in json_data["data"]["reports"][:user_def_max_report]:
            print("\t - ", end="")
            print(report["reporterCountryCode"] + " reported at ", end="")
            print("(" + report["reportedAt"] + ") ", end="")

            # stuff for cutting off the end of reports that are too long
            character_max = 56
            list_comment = [ch for ch in report["comment"]]
            report_len = len(list_comment)
            if report_len >= character_max:
                report_len = character_max
                list_comment[character_max - 3] = '.'
                list_comment[character_max - 2] = '.'
                list_comment[character_max - 1] = '.'
            # remove newlines if they exist
            if '\n' in list_comment:
                list_comment[list_comment.index('\n')] = 'n'

            # join the comment back together, and print
            comment = "".join(list_comment[:report_len])
            print(comment)

    # pritn information about ip report categories
    if user_configs["show"]["ipabusedb"]["reportCategories"]:
        reported_cata = set()
        if len(json_data["data"]["reports"]) >= 1:
            for report in json_data["data"]["reports"]:
                for catagory in report["categories"]:
                    reported_cata.add(catagory)
        print("")
        print("Recent reports keywords: ", end="")
        with open("report_categories.json", "r") as cat_file:
            catagory_dict = json.load(cat_file)
        for catagory in reported_cata:
            print(catagory_dict[str(catagory)][0] + ", ", end="")

    print("\n")


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
    try:
        with open(user_configs["api_keys"]["ipabusedb"], 'r') as file:
            key = file.read()
            key = key.split()
            key = "".join(key)
    except Exception:
        print("error when reading from apikey file")
        return

    # set parameters for the API request
    params = {
        "ipAddress": ip_address,
        "verbose": "True"
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
        # call the print functions
        print("abuseipdb api results:")
        print_abuse_conf_score(json_resp, user_configs)
        print_ip_information(json_resp, user_configs)
        print_domain_information(json_resp, user_configs)
        print_report_data(json_resp, user_configs)
    else:
        # print error message
        print("api call fail")
        print("abuseipdb api response: " + json_resp["errors"][0]["detail"])


def ip_geo_api_call(ip_address, user_configs):
    """ uses IP-API.com to get geolocation info about ip address """

    # call the ip geolocation api
    api_response = requests.get("http://ip-api.com/json/" + str(ip_address))
    json_resp = json.loads(api_response.content.decode("utf-8"))

    # call the print function if the api response was successful
    if json_resp["status"] == "success":
        print_geolocation_info(json_resp, user_configs)
    else:
        print("geolocaltion api call failure.")


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
            ip_geo_api_call(ip_address, user_configs)
        except socket.error:
            print("ip address not detected...")
            pass
        try:
            ip_address = socket.gethostbyname(ip_address)
            print("domain name detected")
            abuseIPDB_API_Call(ip_address, user_configs)
            ip_geo_api_call(ip_address, user_configs)
        except socket.gaierror:
            print("domain name not detected")
            # not ip address, soooo other thing
            if ip_address == 'q':
                print("closing program")
                loop_prompt = False
                # break


if __name__ == "__main__":
    main()
