#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import sys
import selectors
import subprocess
import cherrypy
import signal as sig
from colour import Color


### Customisations. Feel free to edit this to fit your needs


## path to CLI OneShot
from OneShot.oneshot import *

# TODO to be removed
OneShot_path = "./OneShot"


## attributes displayed in table of network scan
# remove ones you don't want to save screen space
# or add more
scan_cols = [["Level", "ESSID"],
            ["Device name", "BSSID"]]

# 3-column version
#scan_cols = [["Level", "ESSID", "Security type"],
#            ["Device name", "BSSID", "WPS"]]


## range for signal level of scanned networks
# used only for choosing corresponding color
# the signal is expected between these values
signal_min = -100
signal_max = -50


## color theme customization :)
color_primary      = Color("#00AA7F").hex_l
# this one is not yet used
color_primary_dark = Color("#007E5C").hex_l
color_accent       = Color("#F81C1F").hex_l

'''
# dark theme
color_bg           = Color("#30363A").hex_l
color_bg_dark      = Color("#282828").hex_l
color_text         = Color("#FCFCFC").hex_l
'''

# light theme
color_bg           = Color("#FCFCFC").hex_l
color_bg_dark      = Color("#FAF5F5").hex_l
color_text         = Color("#282828").hex_l




### Actual code begins


def get_color_by_signal(signal):
    max_color = Color("red")
    min_color = Color("green")
    gradient = list(max_color.range_to(min_color, abs(signal_max - signal_min)))
    
    return gradient[signal - signal_min].hex_l

def parseCSS():
    css = open("style.css").read()
    
    css = css.replace("@color_primary@", color_primary) \
          .replace("@color_accent@", color_accent) \
          .replace("@color_bg@", color_bg) \
          .replace("@color_bg_dark@", color_bg_dark) \
          .replace("@color_text@", color_text)
    
    return css



class OneShot:
    
    def __init__(self, interface, vuln_list):
        self.OneShot_proc = None
        self.scanner = WiFiScanner(interface, vuln_list)
    
        
    def kill(self):
         if self.OneShot_proc != None:
            os.kill(self.OneShot_proc.pid, sig.SIGINT)
            self.OneShot_proc = None
            
    def scan(self):
        return self.scanner.iw_scanner() or []
    
    def run(self, target):
        self.OneShot_proc = subprocess.Popen(["python3", "-u", OneShot_path + "/oneshot.py", "-b", target] + raw_args,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    def get_proc(self):
         return self.OneShot_proc
    
    def get_stored(self):
         return self.scanner.stored
    
    def get_vuln_list(self):
         return self.scanner.vuln_list





class WebUI():
    
    def body(self, title, FABicon, FABlink):
        return """
            <html>
            <head>
                <meta charset="UTF-8">
                <title>{}</title>
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <style>
                {}
                </style>
            </head>
            <body>
            
            <a id="fab" href="{}"">{}</a>
            """.format(title, parseCSS(), FABlink, FABicon)
        
    def header(self):
        return "<a href='help'>help</a>\n" \
                "<a href='/signal?signal=exit'>exit</a>\n"
      
    def footer(self):
        return  "</body>\n" \
                "</html>"
    
    @cherrypy.expose
    def index(self):
        return self.scan()
    
    
    @cherrypy.expose
    def scan(self):
        oneshot.kill()
        
        scan = oneshot.scan()
        html = self.body("Scan", "&#x21BB;", ".")
        html += self.header()
        
        html += "<a>found {} nets</a>\n".format(str(len(scan)))
                
        
        # print the header
        html += "<table width='96%'>\n" \
                "<tr id='header'>" \
                "<td>status</td>"
        for r1, r2 in scan_cols:
            html += "<td>{}<br>{}</td>".format(str(r1), str(r2))
        html += "</tr>\n"
        
        # print scan results
        for ap in scan:            
            html += "<tr><td class='flags' bgcolor={}><a href='go?target={}'>".format(get_color_by_signal(ap["Level"]), ap["BSSID"])
            
            # status flags
            
            # WPS locked
            if ap["WPS locked"]:
                html += "&#x1F512;"     # lock icon
            # Already stored
            if (ap["BSSID"], ap["ESSID"]) in oneshot.get_stored():
                html += "&#x2713;"      # check icon
            # Possibly vulnerable
            if oneshot.get_vuln_list() and ('{} {}'.format(ap["Model"], ap["Model number"]) in oneshot.get_vuln_list()):
                html += "&#x2620;"      # pirate icon
                    
            html += "</a></td>"
            for r1, r2 in scan_cols:
                html += "<td><a href='go?target={}'>{}<br>{}</a></td>" \
                        .format(ap["BSSID"], str(ap[r1]), str(ap[r2]))
            
            html += "</tr>\n"
        
        html += "</table>"
        html += self.footer()
        return str(html)
    
    
    # run the attack
    @cherrypy.expose
    def go(self, target):
        yield self.body("Running...", "X", "signal?signal=CTRL-C")
        yield self.header()
        
        yield "<div id='logareaWrapper'><p id='logarea'>\n"
        
        oneshot.run(target)
        
        sel = selectors.DefaultSelector()
        sel.register(oneshot.get_proc().stdout, selectors.EVENT_READ)
        sel.register(oneshot.get_proc().stderr, selectors.EVENT_READ)

        while True:
            for key, _ in sel.select():
                data = key.fileobj.read1().decode()
                if not data:
                    break
                if key.fileobj is oneshot.get_proc().stdout:
                    yield data.replace("\n", "<br>\n")
                    # this is so that it can be piped to a file
                    print(data, end="")
                else:
                    yield data.replace("\n", "<br>\n")
                    print(data, end="")
        
        yield "</p></div>\n"
        oneshot.kill()
        
        return self.footer()
    
    # for user input
    @cherrypy.expose
    def signal(self, signal):
        if signal == "CTRL-C":
            oneshot.kill()
        
        if signal == "exit":
            yield "exitting..."
            cherrypy.engine.exit()
            return
        
        # redirect to scan
        raise cherrypy.HTTPRedirect("/")
    
    
    # displays the README, without parsing the MD
    @cherrypy.expose
    def help(self):
        try:
            return open("README.md").read().replace("\n", "<br>\n")
        except FileNotFoundError:
            return "README.md not found.<br>\n" \
                    "Get it <a href='https://github.com/eda-abec/OneShot-WebUI/blob/master/README.md'>here</a>"
    
    
    index._cp_config = {"response.stream": True}
    go._cp_config = {"response.stream": True}










# remove this script from args
raw_args = sys.argv[1:]

# remove -t
# not quite pythonic, but does its job
for i in range(len(raw_args)):
    if raw_args[i] == "-t":
        del raw_args[i]


parser = argparse.ArgumentParser (
    description = "OneShot WebUI (c) 2021 eda-abec\n" +
        "based on OneShotPin 0.0.2 (c) 2017 rofl0r, modded by drygdryg",
    epilog = "Usage: same as in OneShot, then connect to localhost:8080"
)

parser.add_argument(
    "-i", "--interface",
    type = str,
    required = True,
    help = "name of the interface to use"
)

parser.add_argument(
    "--vuln-list",
    type = str,
    default = OneShot_path + "/vulnwsc.txt",
    help = "Use custom file with vulnerable devices list"
)

parser.add_argument(
    "-t", "--termux-intent",
    action = "store_true",
    help = "automatically open webpage in browser. Works only in Termux on Android"
)

args, _ = parser.parse_known_args()




if os.getuid() != 0:
    die("Run it as root")

if not ifaceUp(args.interface):
    die('Unable to up interface "{}"'.format(args.interface))

try:
    with open(args.vuln_list, "r", encoding="utf-8") as file:
        vuln_list = file.read().splitlines()
except FileNotFoundError:
    vuln_list = []




if args.termux_intent:
    try:
        subprocess.Popen(["termux-open-url", "http://127.0.0.1:8080"])
    except FileNotFoundError:
        sys.stderr.write("Your shell does not support this. Are you using Termux and have Termux API installed?\n")


oneshot = OneShot(args.interface, vuln_list=vuln_list)

cherrypy.config.update({'log.screen': False,
                        'log.access_file': '',
                        'log.error_file': ''})

cherrypy.quickstart(WebUI())
