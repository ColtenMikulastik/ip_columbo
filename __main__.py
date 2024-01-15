
import requests
import json
import time
import socket


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
        # print info from api call
        # looping through json dictionary, only print user_configs keys
        for d_key, value in json_resp["data"].items():
            if user_configs["show"][d_key]:
                print(str(d_key) + ": " + str(value))
    else:
        # print error message
        print("api call fail")
        print("abuseipdb api response: " + json_resp["errors"][0]["detail"])


def main():
    """ gets user input and calls all the other functions """

    print("loading user configurations...")
    user_configs = load_user_config()
    print("configurations loaded successfully")
    time.sleep(1)

    # print the splash art
    with open("banner.txt", 'r') as banner:
        print(banner.read())

    ip_address = input("ip: ")
    # verify that the inputed data is correct using socket
    try:
        socket.inet_aton(ip_address)
        # continue to API call if ip is valid
        abuseIPDB_API_Call(ip_address, user_configs)
    except socket.error:
        print("non-valid ip address")


if __name__ == "__main__":
    main()
