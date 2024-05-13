#!/bin/env python3

# RXHunter ~ by s0ck37
# Python script to search for reflected XSS vulnerabilites
# https://github.com/s0ck37/rxhunter

import requests
import argparse
from time import sleep
from random import randint
from datetime import datetime
from urllib.parse import urlparse
from random_user_agent.user_agent import UserAgent

RANDOM_AGENT = False
VERIFY = True
DELAY = 0

YELLOW = "\033[33m"
BLUE = "\033[34m"
RED = "\033[31m"
GREEN = "\033[32m"
RESET = "\033[0m"

Agent = UserAgent()

# Wrapped log functions
def pwarning(string): print(f"[{YELLOW}!{RESET}] [{datetime.now().isoformat()}] {string}")
def pinfo(string): print(f"[{BLUE}*{RESET}] [{datetime.now().isoformat()}] {string}")
def perror(string): print(f"[{RED}-{RESET}] [{datetime.now().isoformat()}] {string}")
def psuccess(string): print(f"[{GREEN}+{RESET}] [{datetime.now().isoformat()}] {string}")

# Generate random string for testing
def generate_string(length):
    characters = "abcdefghijklmnopqrstuvwxyz"
    result = ""
    for _ in range(0,length):
        character = randint(0,len(characters)-1)
        result += characters[character]
    return result

# Get length of request
def make_request(url,length=True):
    global VERIFY,RANDOM_AGENT,Agent
    headers = {}
    if RANDOM_AGENT:
        headers = { "User-Agent" : Agent.get_random_user_agent() }
    result = requests.get(url,verify=VERIFY,headers=headers)
    if length:
        return len(result.text)
    else:
        return result.text

# Checking if the input is reflected
def is_reflected(url,name,value):
    global DELAY

    # Generating new query without the target parameter 
    query = url.query
    before_query = ""
    url = url._replace(query="",fragment="").geturl()
    i = 0
    for parameter in query.split("&"):
        if parameter.split("=")[0] != name:
            before_query += parameter
            before_query += "&"
            i += 1
    
    # Making requests with different parameter lengths
    results = []
    for i in range(0,20):
        check_url = url + "?" + before_query + name + "=" + generate_string(i)
        check_result = [i,make_request(check_url)]
        results.append(check_result)
        sleep(DELAY)

    # Checking if the lengths increment
    last_length = results[0][1]
    for request in results:
        if request[1] < last_length:
            pwarning(f"Parameter {BLUE}{name}{RESET} is not reflected in response length")
            break

    # Checking if it is reflected in plain text
    check_value = generate_string(10)
    check_url = url + "?" + before_query + name + "=" + "<" + check_value + ">"
    result = make_request(check_url,length=False)
    if "<"+check_value+">" in result:
        psuccess(f"Parameter {BLUE}{name}{RESET} if {GREEN}vulnerable{RESET} to XSS")
    else:
        pwarning(f"Manually check parameter {BLUE}{name}{RESET} because it may be vulnerable")

def main():
    global RANDOM_AGENT,VERIFY,DELAY

    # Print banner
    print(r"""    ____ _  __ __  ____  ___   __________________ 
   / __ \ |/ // / / / / / / | / /_  __/ ____/ __ \
  / /_/ /   // /_/ / / / /  |/ / / / / __/ / /_/ /
 / _, _/   |/ __  / /_/ / /|  / / / / /___/ _, _/ 
/_/ |_/_/|_/_/ /_/\____/_/ |_/ /_/ /_____/_/ |_|  
                                                  """)

    # Parsing command line arguments
    parser = argparse.ArgumentParser(
            prog="rxhunter",
            description="Command line tool to check for reflected XSS",
    )
    parser.add_argument('url', help="url to test")
    parser.add_argument('-v', '--verify', action='store_true', default=True, help="not verify SSL for requests")
    parser.add_argument('-r', '--random-agent', action='store_true', help="make request with random agent")
    parser.add_argument('-d', '--delay', type=int, default=0, help="delay beetween requests", metavar='D')
    args = parser.parse_args()
    
    # Set global variables
    RANDOM_AGENT = args.random_agent
    VERIFY = args.verify
    DELAY = args.delay

    # Print run details
    print(f" Random agent: {RANDOM_AGENT}")
    print(f" Verify SSL:   {VERIFY}")
    print(f" Delay:        {DELAY}(s)")
    print()

    # Parse the url
    non_parsed_url = args.url
    url = urlparse(non_parsed_url)
    pinfo(f"Searching for reflected XSS at {BLUE}{url.netloc}{RESET}")
    if url.query == "":
        perror("No parameters to test on specified url")
        exit(1)
    
    # Parsing parameters
    parameters = url.query.split("&")
    for parameter in parameters:
        disected = parameter.split("=")
        if len(disected) == 1:
            disected.append("")
        name = disected[0]
        value = disected[1]
        if value == "":
            pwarning(f"No default value for parameter {name} was given")
        is_reflected(url,name,value)

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        perror(f"Error: {error}")
