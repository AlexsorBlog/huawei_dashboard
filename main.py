import sys
import time
import threading
from flask import Flask, render_template, redirect, url_for
from netmiko import ConnectHandler
import re
import configparser
import logging
import os


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create file handler which logs even debug messages
fh = logging.FileHandler('app.log')
fh.setLevel(logging.DEBUG)

# Create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# Create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)

# Clear existing handlers
if logger.hasHandlers():
    logger.handlers.clear()

# Add handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Define the data globally so it is accessible in the route
port_data = []
port_stat = []
transceiver_data = []
data_ready = False

def get_port_info(data, port_name):
    # Split the data into lines
    lines = data.splitlines()
    # Initialize variables
    port_info = []
    collecting = False

    # Loop through each line in the data
    for line in lines:
        # Check if the line contains the target port name at the start
        if line.startswith(port_name):
            collecting = True  # Start collecting lines for the desired port
        elif collecting and line.strip() == "":  # Empty line ends the section
            break
        elif collecting:
            port_info.append(line)

    # Return the collected information as a single string
    return "\n".join(port_info)

def analyze_ports(port_data, detailed):
    good = []
    bad = []
    inactive = []

    for port in port_data:
        interface = port['Interface']
        phy_status = port['PHY']
        protocol_status = port['Protocol']
        in_utilization = port['InUti']
        out_utilization = port['OutUti']
        in_errors = int(port['inErrors'])
        out_errors = int(port['outErrors'])

        issues = []

        # Analyze PHY status
        if phy_status == 'down':
            issues.append("Physical layer failure.")
        elif phy_status == '*down':
            issues.append("Administratively down (shutdown).")
        elif phy_status == '^down':
            issues.append("Backup interface (not in use).")
        elif phy_status == '#down':
            issues.append("Loop detected and interface shut down.")
        elif '(l)' in phy_status:
            issues.append("Loopback function enabled.")
        elif '(b)' in phy_status:
            issues.append("BFD down state detected on physical layer.")
        elif phy_status == 'up (d)':
            issues.append("Interface disabled by device.")
        elif phy_status == 'unreachable':
            issues.append("Interface unreachable.")
        elif phy_status == 'testing':
            issues.append("Interface in testing mode.")

        # Analyze Protocol status
        if protocol_status == 'down':
            issues.append("Link layer protocol failure.")
        elif '(s)' in protocol_status:
            issues.append("Spoofing enabled.")
        elif '(E)' in protocol_status:
            issues.append("Eth-Trunk down due to E-Trunk negotiation failure.")
        elif '(b)' in protocol_status:
            issues.append("BFD down state on link layer.")
        elif '(e)' in protocol_status:
            issues.append("ETHOAM down state.")
        elif '(dl)' in protocol_status:
            issues.append("DLDP down state.")
        elif '(lb)' in protocol_status:
            issues.append("Blocked due to loops.")
        elif '(ms)' in protocol_status:
            issues.append("MACsec down state (MACsec disabled on peer).")
        elif protocol_status == 'admin-down':
            issues.append("Admin down - protocol administratively disabled.")
        elif protocol_status == 'up (m)':
            issues.append("Maintenance mode active.")

        # Analyze Utilization
        in_util = float(in_utilization.strip('%')) if in_utilization != '--' else None
        out_util = float(out_utilization.strip('%')) if out_utilization != '--' else None

        if in_util is not None:
            if in_util >= 90:
                issues.append("High inbound utilization (possible congestion).")
            elif in_util < 5:
                issues.append("Low inbound utilization (may indicate inactivity).")
        if out_util is not None:
            if out_util >= 90:
                issues.append("High outbound utilization (possible congestion).")
            elif out_util < 5:
                issues.append("Low outbound utilization (may indicate inactivity).")

        # Analyze Errors
        if in_errors > 0:
            issues.append(f"Received error packets: {in_errors}")
        if out_errors > 0:
            issues.append(f"Sent error packets: {out_errors}")
        if in_errors > 1000:
            issues.append("High rate of inbound errors.")
        if out_errors > 1000:
            issues.append("High rate of outbound errors.")

        detailed_port = get_port_info(detailed, interface)
        try:
            detailed_port = detailed_port.replace("-", "")
        except:
            pass

        detailed_port = detailed_port.split("\n")

        # Mark as inactive if both inbound and outbound utilization are very low
        if in_util is not None and out_util is not None and ( in_util < 5 or out_util < 5):
            inactive.append({"port": interface, "issues": ["Port inactive due to low utilization."], "status": "INACTIVE", "detailed": detailed_port})
        elif issues:
            bad.append({"port": interface, "issues": issues, "status": "ISSUE", "detailed": detailed_port})
        else:
            good.append({"port": interface, "status": "GOOD", "detailed": detailed_port})

    return [good, bad, inactive]

def Get_massive(raw_output):
    massive = []
    lines = raw_output.strip().splitlines()
    headers = lines[0].split()
    for line in lines[1:]:
        values = line.split()
        interface_info = dict(zip(headers, values))
        massive.append(interface_info)
    return massive

def create_connection(host, username, password):
    device = {
        "device_type": "huawei",
        "host": host,
        "username": username,
        "password": password,
        "conn_timeout": 20,
        "auth_timeout": 20,
        "banner_timeout": 20,
    }
    try:
        connection = ConnectHandler(**device)
        connection.send_command("screen-length 0 temporary")
        return connection
    except Exception as e:
        print(f"Error: {e}")
        return None

def execute_command(connection, command):
    try:
        output = connection.send_command(command)
        return output
    except Exception as e:
        print(f"Error executing command: {e}")
        return None

def close_connection(connection):
    if connection:
        connection.disconnect()
        print("Connection closed.")

def clean_up_info(info):
    # Replace multiple spaces with a single space and strip leading/trailing spaces
    return re.sub(r'\s+', ' ', info).strip()

def parse_transceiver_info(raw_output):
    ports_data = []
    interfaces = raw_output.split("\n\n")  # Split by double newline to separate each port section

    for interface_info in interfaces:
        # Match the interface name at the beginning of each section
        interface_match = re.search(r"(\S+?)\s+transceiver information:", interface_info)
        if not interface_match:
            continue  # Skip sections without a valid interface header

        # Extract the interface name
        interface_name = interface_match.group(1)

        # Collect "Common information" as a whole block
        common_info_match = re.search(
            r"Common information:\n(.*?)\n-------------------------------------------------------------",
            interface_info, re.DOTALL)
        common_info = common_info_match.group(1).strip() if common_info_match else ""
        common_info = clean_up_info(common_info)  # Clean up common info

        # Collect "Manufacture information" as a whole block
        manufacture_info_match = re.search(
            r"Manufacture information:\n(.*?)\n-------------------------------------------------------------",
            interface_info, re.DOTALL)
        manufacture_info = manufacture_info_match.group(1).strip() if manufacture_info_match else ""
        manufacture_info = clean_up_info(manufacture_info)  # Clean up manufacture info

        # Collect "Alarm information" as a whole block if it exists
        alarm_info_match = re.search(
            r"Alarm information:\n(.*?)\n-------------------------------------------------------------", interface_info,
            re.DOTALL)
        alarm_info = alarm_info_match.group(1).strip() if alarm_info_match else ""
        alarm_info = clean_up_info(alarm_info)  # Clean up alarm info

        # Add the parsed data to the list as an individual port entry
        port_entry = {
            "interface": interface_name,
            "common": common_info,  # Include all common information unfiltered
            "manufacture": manufacture_info,
            "alarm": alarm_info
        }

        ports_data.append(port_entry)  # Append each port entry to the list

    return ports_data



def fetch_switch_data(host, username, password, refresh_time):
    global port_data, port_stat, data_ready, transceiver_data
    logger.info("START CONNECTION\n---------------")
    try:
        connection = create_connection(host, username, password)
        if connection:
            logger.info("CONNECTED")
        else:
            logger.warning("CONNECTION FAILED\nRETRYING...")
            time.sleep(10)
            connection = create_connection(host, username, password)
            if connection:
                logger.info("CONNECTED")
            else:
                logger.error("RETRY FAILED\nEXITING")
                os._exit(0)
    except Exception as e:
        logger.exception(f"Exception occurred: {e}")
        return

    while True:
        if connection:
            try:
                logger.info("PARSING DATA...")
                brief = execute_command(connection, "display interface brief")
                transceiver_brief = execute_command(connection, "display transceiver")
                if brief:
                    brief = brief.split("InUti/OutUti: input utility/output utility\n")[1]
                    transceiver_data = parse_transceiver_info(transceiver_brief)
                    detailed_ports_str = execute_command(connection, "display interface")
                    massive = Get_massive(brief)
                    ports_info = analyze_ports(massive, detailed_ports_str)
                    good_ports, bad_ports_info, inactive = ports_info

                    port_data = good_ports + bad_ports_info + inactive
                    port_stat = [len(good_ports), len(bad_ports_info), len(inactive), len(massive)]
                    data_ready = True  # Data is ready
                    logger.info("DATA PARSED AND READY")
                    for port in port_data:
                        logger.debug(f"Port: {port['port']}, Status: {port['status']}, Issues: {port.get('issues', 'No issues')}, Detailed information: {port.get('detailed')}")
                else:
                    logger.warning("Commands didn't work")
                logger.info("DATA PARSED AND DISPLAYED")
            except Exception as e:
                logger.exception(f"Exception occurred while parsing data: {e}")
        else:
            logger.error("CONNECTION ERROR")

        time.sleep(refresh_time)
    close_connection(connection)

@app.route('/')
def index():
    if data_ready:
        return render_template('index.html', ports=port_data, statistic=port_stat)
    else:
        return redirect(url_for('loading'))

@app.route('/loading')
def loading():
    return render_template('loading.html')

@app.route('/transceiver')
def transceiver():
    if data_ready:
        return render_template('transceiver.html', transceivers=transceiver_data)
    else:
        return redirect(url_for('loading'))

def read_config():
    # Create a ConfigParser object
    config = configparser.ConfigParser()

    # Read the configuration file
    config.read('config.ini')

    return config

if __name__ == '__main__':
    config_data = read_config()
    logger.info("SETTINGS")
    refresh_time = config_data["General"]["refresh_delay"]
    logger.info(f"REFRESH DELAY: {refresh_time}")
    host = config_data["General"]["host"]
    logger.info(f"HOST/IP: {host}")
    username = config_data["General"]["login"]
    logger.info(f"USERNAME/LOGIN: {username}")
    password = config_data["General"]["password"]
    logger.info(f"PASSWORD: {password}")
    threading.Thread(target=fetch_switch_data, daemon=True, args=(host, username, password, int(refresh_time))).start()
    local_host = config_data["General"]["local_host"]
    local_port = config_data["General"]["local_port"]
    logger.info("-------------")
    logger.info(f"PROGRAM RUNNING IN http://{local_host}:{local_port}/")
    logger.info("-------------")
    app.run(host=local_host, port=int(local_port))
