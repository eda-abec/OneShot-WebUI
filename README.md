# Web Graphical Interface for OneShot

**WebUI** is a wrapper for [OneShot](https://github.com/drygdryg/OneShot) that provides a convenient way to control it on a smartphone.

The HTML page is designed to be as minimal as possible, with no JS and only pure CSS, while mimicking Material Design.


## Usage

Options are same as for OneShot, with one extra option:\
`-t/--termux-intent` in Termux, sends an intent to open the webpage in a browser

When running, navigate to [localhost, port 8080](http://127.0.0.1:8080).

All OneShot `print()`s are also sent to `stdout`, so they can be logged to a file.


### Status flags

- &#x1F512; AP is locked
- &#x2713; network is already in `stored.csv`
- &#x2620; router model is in the list of vulnerable models
- color of the status cell visually represents signal strength


## Customizations

At the beginning of this script is a section with variables to be changed according to users needs. Featuring:
- light theme / dark theme
- network attributes displayed in scan


## TODOs

- improve OneShot state handling
- autoscroll down in `/go`
- documentation and comments in code
- responding to prompts - "Use previous calculated PIN" etc...
- CSS cleanup
- use library for generating HTML
- checkboxes for filtering
    - locked networks, stored networks
    - too verbose output


### Graphical TODOs

- better FAB design (icon is not centered)
- rework status column design for more clarity
- "ergonomic" UI version (like curved Android software keyboards)
- top bar with buttons and more thoughtful design


## Implementation

The web page is served by [Cherrypy](https://cherrypy.org/). OneShot functionality is accessed through wrapper class. This class provides two main features - network scanning and running OneShot attack. For scanning, this script uses functions from OneShot as a library (the code is imported to the main file), whereas for the attack, OneShot script is run in a subprocess.

All arguments except `-t/--termux-intent` are not checked and are evaluated in OneShot subprocess.


### Endpoints

- `/index`, `/scan` provide scan results
- `/go` has parameter `target`, specifying MAC address of target
- `/signal` used to send a signal to the script by parameter `signal`. Currently, `CTRL-C` and `exit` is supported
- `/help` only prints this file, with no formatting


## Acknowledgements

Author: [eda-abec](https://github.com/eda-abec)\
Date: 02/2021\
Thanks for amazing work on CLI version to:
- [rofl0r](https://github.com/rofl0r/)
- [drygdryg](https://github.com/drygdryg/)
