
from rate_limit import rate_limit
from requests.api import head
from termcolor import colored
import requests
import json
import socket
import os


def auto_reporting_ip_abuse(ip_address, user_configs):
    """ reports user to ipabusedb via api"""

    # unload the catagory file
    catagory_dict = unload_catagory_file()

    # auto reporting if the user wants it
    print("please select the report category this ip is connected with.")
    print("0 - to cancel without reporting, ")
    cat_num = 1
    while cat_num <= 23:
        row = 0
        while row <= 2:
            if cat_num >= 24:
                pass
            else:
                print(str(cat_num) + " - " + catagory_dict[str(cat_num)][0] + ", ", end="\t")
            cat_num = cat_num + 1
            row = row + 1
        print()
    report_cat = input("please type a number for the report catagory:")

    if report_cat == 0:
        return
    else:
        # unload ipabuse db api key
        try:
            with open(user_configs["api_keys"]["ipabusedb"], 'r') as file:
                key = file.read()
                key = key.split()
                key = "".join(key)
        except Exception:
            print("error when reading from apikey file")
            return

        # set up parameters for the api
        params = {
            "ipAddress": ip_address,
            "verbose": "True"
        }
        headers = {
            "Key": key,
            "Accept": "application/json"
        }
        data = {
            "ip": ip_address,
            "categories": report_cat
        }

        # send post to api
        url = "https://api.abuseipdb.com/api/v2/report"
        response = requests.post(url, params=params, data=data, headers=headers)

        # check if successful or not
        if response.status_code == 200:
            print("successful post to ipabusedb")
        else:
            print("error occured")
    return



def print_malware_bazaar_info(json_data, user_configs):
    """ print the information from the malware bazaar api """
    print(json_data)
    print(type(json_data))

    # printing the timestamp information if wanted
    if user_configs["show"]["malware_bazaar"]["hashes"]:
        print("Hash Information:")
        print("\tsha256:\t" + str(json_data["data"][0]["md5_hash"]))
        print("\tsha384:\t" + str(json_data["data"][0]["sha3_384_hash"]))
        print("\tsha1:\t" + str(json_data["data"][0]["sha1_hash"]))
        print("\tmd5:\t" + str(json_data["data"][0]["md5_hash"]))

    # printing the timestamp information if wanted
    if user_configs["show"]["malware_bazaar"]["timestamps"]:
        print("Time Information:")
        print("\tfirst seen:\t" + str(json_data["data"][0]["first_seen"]))
        print("\tlast seen:\t" + str(json_data["data"][0]["last_seen"]))

    # printing the file information if wanted
    if user_configs["show"]["malware_bazaar"]["file_info"]:
        print("File Information:")
        print("\tfile name:\t" + str(json_data["data"][0]["file_name"]))
        print("\tfile size:\t" + str(json_data["data"][0]["file_size"]))
        print("\tfile type:\t" + str(json_data["data"][0]["file_type"]))
        print("\tMIME type desc:\t" + str(json_data["data"][0]["file_type"]))

    # printing the reporting information if wanted
    if user_configs["show"]["malware_bazaar"]["reporter_info"]:
        print("Reporting Information:")
        print("\treporter:\t" + str(json_data["data"][0]["reporter"]))
        print("\treport country:\t" + str(json_data["data"][0]["origin_country"]))

    if user_configs["show"]["malware_bazaar"]["tags"]:
        print("Associated Tags: ", end='')
        for tag in json_data["data"][0]["tags"]:
            print(str(tag) + ",", end='')
        print()

    # signatures are being finicky
    # if user_configs["show"]["malware_bazaar"]["code_sign"]:
    #     print("Code Signatures: ", end='')
    #     for sign in json_data["data"][0]["code_sign"]:
    #         print("\t- " + str(sign))
    #     print()

    # printing delivery method
    if user_configs["show"]["malware_bazaar"]["delivery_method"]:
        print("Reported Mode of Delivery: ", end='')
        print(str(json_data["data"][0]["delivery_method"]))

    # printing yara stuff if it's there
    if user_configs["show"]["malware_bazaar"]["yara_rules"]:
        print("YARA Results:")
        if json_data["data"][0]["yara_rules"] is not None:
            max_rule_print = user_configs["show"]["malware_bazaar"]["yara_rule_Number"]
            for rule in json_data["data"][0]["yara_rules"][:max_rule_print]:
                print("\t" + str(rule["author"]) + ": " + str(rule["rule_name"]))
                if rule["description"] is not None:
                    print("\t\t- description:\t" + str(rule["description"]))
                if rule["reference"] is not None:
                    print("\t\t- reference:\t" + str(rule["reference"]))
        else:
            print("none")

    # print the ole info
    if user_configs["show"]["malware_bazaar"]["ole_info"]:
        if len(json_data["data"][0]["ole_information"]) == 0:
            print("No oleinfo Results...")
        else:
            print("oleinfo Results:")
            print(json_data["data"][0]["ole_information"])

    # heres where I'm gonna put the vendor intel section
    # if user_configs["show"]["malware_bazaar"]["vendor_intel"]:
    #     print(str(json_data["data"][0]["vendor_intel"]))

    # print the comments info
    if user_configs["show"]["malware_bazaar"]["comments"]:
        if json_data["data"][0]["comments"] is not None:
            print(json_data["data"][0]["comments"])
        else:
            print("no comment information...")




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


def unload_catagory_file():
    catagory_dict = dict()
    with open("report_categories.json", "r") as cat_file:
        catagory_dict = json.load(cat_file)
    return catagory_dict


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

    # unload catagory files for this section
    catagory_dict = unload_catagory_file()

    # pritn information about ip report categories
    if user_configs["show"]["ipabusedb"]["reportCategories"]:
        reported_cata = set()
        if len(json_data["data"]["reports"]) >= 1:
            for report in json_data["data"]["reports"]:
                for catagory in report["categories"]:
                    reported_cata.add(catagory)
        print("")
        print("Recent reports keywords: ", end="")
        for catagory in reported_cata:
            print(catagory_dict[str(catagory)][0] + ", ", end="")

    # call the reporting
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


def check_for_hash(input_str):
    """ validates if input is hash by checking length and characters """
    # check if only hexadecimal digits
    # going to use this cheeky character check I found
    allowed_characters = set("0123456789abcdefABCDEF")
    if not set(input_str) <= allowed_characters:
        # too many types of characters, return false
        return False
    else:
        # check if it's a common hash format (sha256, sha1, md5)
        # len of str * 4
        match len(input_str):
            case 64:
                # Checks for sha256
                return True
            case 40:
                # Checks for Sha1
                return True
            case 32:
                # Checks for md5
                return True
            case 96:
                # Checks for sha384 (not supported by malware bazzar api
                print("Sorry: sha384 is not supported")
                return False
            case _:
                return False


def load_rate_limit_file(rate_limit_thing, file_name):
    """ loads rate limit information saved in the log file if it exists """
    full_path = os.path.realpath(os.path.join("log", file_name + "log.json"))
    try:
        with open(full_path, 'r') as f:
            json_out = json.load(f)
            rate_limit_thing.set_first_request_time(json_out["time"])
            rate_limit_thing.set_api_context(json_out["context"])
            print("previous context loaded...")
    except FileNotFoundError:
        print("previous log file not found, continuing w/o context")

    return rate_limit_thing


def write_rate_limit_file(rate_limit_thing, file_name):
    """ writes rate limit information to the log.json file """

    dict_rate_limit_info = {}
    dict_rate_limit_info["time"] = rate_limit_thing.get_first_request_time()
    dict_rate_limit_info["context"] = rate_limit_thing.get_api_context()

    # make sure that file path actually exists
    log_file_exist = os.path.exists(os.path.realpath("log"))
    if not log_file_exist:
        os.mkdir(os.path.realpath("log"))

    # write log files
    full_path = os.path.realpath(os.path.join("log", file_name + "log.json"))
    with open(full_path, 'w') as f:
        json.dump(dict_rate_limit_info, f)


def load_user_config():
    """ loads user configuration json file into dictionary """

    # gonna let the json error checking take care of itself
    with open("user_config.json", 'r') as conf_file:
        user_configs = json.load(conf_file)

    return user_configs


def abuseIPDB_API_Call(ip_address, user_configs, ip_abuse_rate_limiter):
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

    # call api if we are within limits
    if ip_abuse_rate_limiter.update_context():
        api_response = requests.get("https://api.abuseipdb.com/api/v2/check",
                                    params=params,
                                    headers=headers)
    else:
        print("ipabusedb api call not within rate limits!")
        print("try again in a minute!")
        return

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


def ip_geo_api_call(ip_address, user_configs, ip_geoloc_rate_limiter):
    """ uses IP-API.com to get geolocation info about ip address """

    # call the ip geolocation api if within limits
    if ip_geoloc_rate_limiter.update_context():
        api_response = requests.get("http://ip-api.com/json/" + str(ip_address))
    else:
        print("geoloc api call not within rate limits!")
        print("try again in a minute!")
        return

    # turn jsonified
    json_resp = json.loads(api_response.content.decode("utf-8"))

    # call the print function if the api response was successful
    if json_resp["status"] == "success":
        print_geolocation_info(json_resp, user_configs)
    else:
        print("geolocaltion api call failure.")


def malware_bazaar_api_call(hash, user_configs):
    """ uses malware bazaar api to get info about possibly malicous hash """

    # attempt to load api key
    try:
        with open(user_configs["api_keys"]["malwarebazaar"], 'r') as file:
            key = file.read()
            key = key.split()
            key = "".join(key)
    except Exception:
        print("error when reading from apikey file")
        return

    # load the data and headers
    data = {
        "query": "get_info",
        "hash": hash
    }
    headers = {
        "API-KEY": key
    }

    # call api
    response = requests.post("https://mb-api.abuse.ch/api/v1/", data=data, timeout=15, headers=headers)
    # send api data to printing function
    json_resp = json.loads(response.content.decode("utf-8"))

    if json_resp["query_status"] == "ok":
        print_malware_bazaar_info(json_resp, user_configs)
    else:
        print("Malware Bazaar api call failure.")
        print(json_resp)


def main():
    """ gets user input and calls all the other functions """

    print("loading user configurations...")
    user_configs = load_user_config()
    print("configurations loaded successfully")

    # ip abuse db 1000 req per day
    ip_abuse_rate_limiter = rate_limit(1000, 86400)
    # ip geoloc db is 45 req per min
    ip_geoloc_rate_limiter = rate_limit(45, 60)

    # load log from log.json file for rate limit context
    # malware bazaar is super chill so no rate limit needed
    ip_abuse_rate_limiter = load_rate_limit_file(ip_abuse_rate_limiter, "ip_abuse")
    ip_geoloc_rate_limiter = load_rate_limit_file(ip_geoloc_rate_limiter, "ip_geoloc")

    loop_prompt = True
    while loop_prompt:
        # print the splash art
        with open("banner.txt", 'r') as banner:
            print(banner.read())

        # print the options for the prompt
        print("- enter 'q' to quit")

        ip_address = input("ip: ")
        # verify that the inputed data is correct using socket
        is_acceptable_input = False

        try:
            socket.inet_aton(ip_address)
            # continue to API call if ip is valid
            print("ip address detected...")
            is_acceptable_input = True
        except socket.error:
            print("ip address not detected...")
            pass
        try:
            ip_address = socket.gethostbyname(ip_address)
            print("domain name detected")
            is_acceptable_input = True
        except UnicodeError:
            # error thrown when characters in string exceed 64
            print("input string too long, unexpected results could occur (if domain-name)")
        except socket.gaierror:
            print("domain name not detected")
            # not ip address, soooo other thing
            if ip_address == 'q':
                print("closing program")
                print("writing to log files")
                write_rate_limit_file(ip_abuse_rate_limiter, "ip_abuse")
                write_rate_limit_file(ip_geoloc_rate_limiter, "ip_geoloc")
                loop_prompt = False
                # break
        # check if it's a hash
        if check_for_hash(ip_address):
            # send to malware bazaar api
            malware_bazaar_api_call(ip_address, user_configs)
        elif is_acceptable_input:
            abuseIPDB_API_Call(ip_address, user_configs, ip_abuse_rate_limiter)
            ip_geo_api_call(ip_address, user_configs, ip_geoloc_rate_limiter)
            if user_configs["show"]["ipabusedb"]["auto_reporting"]:
                auto_reporting_ip_abuse(ip_address, user_configs)


if __name__ == "__main__":
    main()
