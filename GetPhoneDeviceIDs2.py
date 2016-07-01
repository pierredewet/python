from bs4 import BeautifulSoup
import cookielib
import urllib
import urllib2
import ssl
import argparse
import re
import sys


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filename", required=False,
                        help="input file with a list of ip addresses, one per line", 
                        metavar="FILE")
    parser.add_argument("-i", "--ip_address", required=False,
                        help="Check deviceid for single ip")
    #  Print help and exit if no args supplied
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    #  ip regex (I was lazy): https://www.safaribooksonline.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html
    ipaddress = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

    if args.ip_address:
        if is_valid_ip_address(args.ip_address, ipaddress):
            print "IP, BaseID"
            get_device_id(args.ip_address, 3)
        else:
            print "IP address invalid? (%s) Try again" % (args.ip_address)

    if args.filename:
        try:
            file = open(args.filename)
            IPRange = file.readlines()
        except IOError:
            print "Well that file doesn't exist..."
        else:
            file.close()
            print "IP, BaseID"
            for ip in IPRange:
                if not is_valid_ip_address(ip, ipaddress):
                    print "IP Address incorrect: %s" % (ip)
                else:
                    get_device_id(ip.rstrip(), 3)


def get_device_id(ip, version):
    user_agent = ('Mozilla/5.0 (Windows NT 6.1) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/41.0.2228.0 Safari/537.36')
    prefix = 'https://'
    suffix = '/page.cmd'

    # Store the cookies and create an opener that will hold them
    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

    # Add our headers
    opener.addheaders = [('User-agent', user_agent)]

    urllib2.install_opener(opener)

    # Ignore Self-signed SSL cert
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    authentication_url = prefix + ip + suffix
    # Build our Request object (supplying 'data' makes it a POST)
    if version == 3:
        data = urllib.urlencode(get_payload(3))
    else:
        data = urllib.urlencode(get_payload(2))

    try:
        # Make the request and read the response
        req = urllib2.Request(authentication_url, data)
        resp = urllib2.urlopen(req, context=ssl_context)
    # HTTP Error check needs to be checked before URL Error
    except urllib2.HTTPError as e:
        print "Server request error (%s) : Error - %s" % (ip, e.code)
    except urllib2.URLError as e:
        print "IP address invalid? (%s) : Error - %s" % (ip, e.reason)
    else:
        contents = resp.read()
        soup = BeautifulSoup(contents, "html.parser")
        # Field name containing device id
        viewstate = soup.findAll('input', {'type': 'text', 'name': 'e164'})
        if viewstate:
            device_id = viewstate[0]['value']
            print "%s,%s" % (ip, device_id)
        else:  # prior version
            get_device_id(ip, 2)


def get_payload(version):
    #  Common
    language = 'en'
    default_page = 'WEBM_Admin_Identity'
    username = 'user'
    password = 'password'

    payload_v3 = {  # Device software version 3
        'page': default_page,
        'lang': language,
        'page_submit': 'WEBMp_Admin_Login',
        'page-next': default_page,
        'user': username,
        'AdminPassword': password
    }

    payload_v2 = {  # Device software version 2
        'page': default_page,
        'lang': language,
        'page_submit': 'WEBMp_AdminLogin',
        'page-next': default_page,
        'WEBMv-Admin-Password': password
    }

    if version == 3:
        return payload_v3
    else:
        return payload_v2


def is_valid_ip_address(ip, ipaddress):
    if ipaddress.match(ip):
        return True
    return False


if __name__ == "__main__":
    run()
