#!/usr/bin/python

import socket
from itertools import product
from time import sleep

tld_mapping = {
}

def get_whois_server(tld):
    whois = 'whois.iana.org'
    msg = perform_whois(whois, tld)
    print(msg)
    # Now search the reply for a whois server

    lines = [x for x in msg.splitlines() if x != '' and ':' in x]
    d = {line.split(':', 1)[0].strip(): line.split(':', 1)[1].strip() for line in lines}
    print(d)
    if 'whois' in d:
        whois = d['whois']
        tld_mapping[tld] = whois
    return whois

# Perform a generic whois query to a server and get the reply
def perform_whois(server, query):
    # socket connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 43))

    # send data
    s.send(query + '\r\n')

    # receive reply
    msg = ''
    while len(msg) < 10000:
        chunk = s.recv(100)
        if (chunk == ''):
            break
        msg = msg + chunk

    return msg


# Function to perform the whois on a domain name
def get_whois_data(domain):
    domain = domain.replace('http://', '')
    domain = domain.replace('www.', '')

    # get tld
    tld = domain.split('.')[-1]

    if tld not in tld_mapping:
        whois = get_whois_server(tld)
    whois = tld_mapping[tld]

    msg = perform_whois(whois, domain)

    return msg


def make_combinations(length, characters='abcdefghijklmnopqrstuvwxyz0123456789'):
    return (''.join(p) for p in product(characters, repeat=length))


if __name__ == '__main__':
    import sys
    import pickle
    import json

    print('Usage: whois.py [topleveldomain] [domainlength] [sleeptime_ms]')
    print('Example: whois.py de 3 1000')
    args = sys.argv
    if sys.argv != 4:
        print('exiting.. not enough parameters')
        exit()

    tld = args[1]
    length = args[2]
    sleeptime = args[3]

    try:
        done = pickle.load(open('done_{}.p'.format(tld)))
    except:
        done = set()

    try:
        found = pickle.load(open('found_{}.p'.format(tld)))
    except:
        found = set()

    domains = list(make_combinations(length))

    print('looking up', len(domains), 'domains')
    print(len(done), 'done')
    print(len(found), 'found')

    for dom in sorted(domains):
        dom += tld

        if dom in done or dom in found:
            continue

        r = get_whois_data(dom)
        sleep(sleeptime / 1000)
        if '55000000002' in r:
            print('### LIMIT EXCEEDED')
            sys.exit()

        r = r.split('\n')

        status = r[1].split(':')[1].strip()
        if status == 'free':
            found.add(dom)
            pickle.dump(found, open("found_{}.p".format(tld), "wb"))
            json.dump(list(found), open("found_{}.json".format(tld), "wb"), indent=2)
            print(dom, len(found), len(done), len(domains))

        done.add(dom)
        pickle.dump(done, open("done_{}.p".format(tld), "wb"))
