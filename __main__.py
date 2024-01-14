
import requests
import json
import time


def load_user_config():
    """ loads user configuration json file into dictionary """

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

    print(user_configs)

    for d_key, value in json_resp["data"].items():
        if user_configs["show"][d_key]:
            print(str(d_key) + ": " + str(value))


def main():
    """ gets user input and calls all the other functions """

    print("loading user configurations...")
    user_configs = load_user_config()
    print("configurations loaded successfully")
    time.sleep(1)

    # print the splash art
    print("===========================")
    print("ip_columbo (the ip checker)")
    print("===========================")

    ip_address = input("ip: ")
    abuseIPDB_API_Call(ip_address, user_configs)


if __name__ == "__main__":
    main()
