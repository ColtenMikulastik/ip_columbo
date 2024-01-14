
import requests
import json

user_configs = {}




def abuseIPDB_API_Call(ip_address):
    """ uses abuseIPDB_API_Call gets JSON """
    # unpack my api key
    # might require fix later
    with open("AbuseIPDB_API_Key.key", 'r') as file:
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

    for key, value in json_resp["data"].items():
        print(str(key) + ": " + str(value))


def main():
    """ gets user input and calls all the other functions """
    print("===========================")
    print("ip_columbo (the ip checker)")
    print("===========================")

    ip_address = input("ip: ")
    print(ip_address)
    abuseIPDB_API_Call(ip_address)


if __name__ == "__main__":
    main()
