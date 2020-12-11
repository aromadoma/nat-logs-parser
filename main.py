from netmiko.ssh_exception import AuthenticationException, NetMikoTimeoutException
from netmiko import ConnectHandler, file_transfer
import gzip
import json
import re
import ipaddress
import os
from datetime import date, time, datetime, timedelta


def connection_to_server(ssh_username, ssh_password, device_ip):
    """

    :param ssh_username: str, username for an ssh connection
    :param ssh_password: str, password for an ssh connection
    :param device_ip: str, ip address of device
    :return: connection, established via netmiko
    """
    connection_settings = {
        'device_type': 'linux',
        'ip': device_ip,
        'username': ssh_username,
        'password': ssh_password
    }

    i = 0

    while i < 3:  # 3 tries to connect
        try:
            ssh_connection = ConnectHandler(**connection_settings)
        except AuthenticationException:
            print(r'Wrong username\password. Please, check credentials.')
            i += 1
        except NetMikoTimeoutException:
            print(f'Syslog is unreachable for now. Trying again...')
            i += 1
        else:
            # print('Successfully authenticated.')
            return ssh_connection

    print(f'Cannot connect to syslog. Skipping')
    return None


def validate_user_input(user_input):
    user_data = {}
    string = re.search(r'(\S+) (\S+ \S+) (\S+ \S+)', user_input)
    if string is None:
        print('Please, check for entered data.\n')
        return None

    # Validating ip address:
    try:
        user_data['public_ip'] = ipaddress.ip_address(string.group(1))
    except ValueError:
        print('ERROR: IP address is invalid.')
        return None
    if user_data['public_ip'].is_private:
        print('ERROR: IP address is private.')
        return None

    # Validating start date and time:
    try:
        user_data['start_datetime'] = datetime.fromisoformat(string.group(2))
    except ValueError:
        print('ERROR: Start date or time is invalid.')
        return None
    if user_data['start_datetime'] > datetime.today():
        print('ERROR: Start date or time is in the future.')
        return None

    # Validating stop date and time:
    try:
        user_data['stop_datetime'] = datetime.fromisoformat(string.group(3))
    except ValueError:
        print('ERROR: Stop date or time is invalid.')
        return None
    if user_data['stop_datetime'] > datetime.today():
        print('ERROR: Stop date or time is in the future.')
        return None
    elif user_data['stop_datetime'] < user_data['start_datetime']:
        print('ERROR: End time less than start time.')
        return None

    return user_data


def search_for_cgnat_name(ip_address, nat_pools):
    for key in nat_pools:
        if ip_address in ipaddress.ip_network(key):
            cgn_hostname = nat_pools[key]
            print(f'This ip belongs to {key} pool on {cgn_hostname}.')
            return cgn_hostname
    print('SORRY. This ip don\'t belongs to any nat pool. Please, check the ip.')


def calculate_archive_date(start_datetime):
    archiving_time = time.fromisoformat('06:25')
    if archiving_time < start_datetime.time() and start_datetime.date() < date.today():
        archive_date = start_datetime.date() + timedelta(days=1)
    elif archiving_time < start_datetime.time() and start_datetime.date() == date.today():
        archive_date = 'TODAY'
    else:
        archive_date = start_datetime.date() - timedelta(days=1)

    return archive_date


def get_specific_period_logs(archive_name, search_data):
    path_to_archive = os.path.join(os.path.dirname(__file__), archive_name)
    specific_period_logs = []
    additional_period_logs = []
    # timedelta = timedelta(minutes=30)
    if '.gz' in archive_name:
        with gzip.open(path_to_archive) as f:
            for line in f:
                log_datetime = datetime.fromisoformat(re.search(r'^(\S+)\+03:00', line.decode('utf-8')).group(1))
                if search_data['start_datetime'] <= log_datetime <= search_data['stop_datetime']:
                    specific_period_logs.append(line.decode('utf-8').rstrip('\n'))
                elif search_data['stop_datetime'] <= log_datetime <= search_data['stop_datetime'] + timedelta(minutes=30):
                    additional_period_logs.append(line.decode('utf-8').rstrip('\n'))
                elif log_datetime > search_data['stop_datetime'] + timedelta(minutes=30):
                    break
            return specific_period_logs, additional_period_logs
    else:
        with open(path_to_archive) as f:
            pass


def main():
    # Path to parameters file:
    parameters_path = os.path.join(os.path.dirname(__file__), 'parameters.json')
    with open(parameters_path) as parameters_file:
        # Loading parameters:
        parameters = json.load(parameters_file)
        ssh_username = parameters['ssh_username']
        ssh_password = parameters['ssh_password']
        device_ip = parameters['device_ip']
        nat_pools = parameters['nat_pools']

    shit_counter = 0

    # Loop for the whole script:
    while True:
        # Waiting for valid user data to be entered:
        print('This script searches private ip addresses which been translated by nat')
        while True:
            if shit_counter < 5:
                print('The format should be used for request: <public_ip> <start_date> <start_time> <stop_date> <stop_time>')
            else:
                print('Ah shit, here we go again.')
            print('An example: 11.1.1.1 2020-09-01 19:56 2020-09-01 20:05')

            # Entering data and checking if it's valid:
            search_data = validate_user_input(input('What are we searching?> '))
            if search_data is not None:
                shit_counter = 0
                break
            else:
                shit_counter += 1

        # Searching for a CGN hostname:
        cgn_hostname = search_for_cgnat_name(search_data['public_ip'], nat_pools)

        # Calculating the needed archive date:
        archive_date = calculate_archive_date(search_data['start_datetime'])

        # Connecting to syslog server:
        print('Connecting to the syslog server... ')
        ssh_connection = connection_to_server(ssh_username, ssh_password, device_ip)
        if archive_date != 'TODAY':
            server_output = ssh_connection.send_command(
                f'ls -oh --sort=time --time-style="long-iso" /var/log/{cgn_hostname}/ | grep "{archive_date}"')
            archive_name = re.search(r'secured-pba\.log\.\d+\.gz', server_output).group()
        else:
            archive_name = 'secured-pba.log'

        # Downloading a log file:
        print(f"Path to log file: '/var/log/{cgn_hostname}/{archive_name}', date is {archive_date}.")
        print('Downloading the log file... ')
        file_transfer(ssh_connection, source_file=archive_name, dest_file=archive_name,
                      file_system=f'/var/log/{cgn_hostname}/', direction='get', overwrite_file=True)

        # Opening the log file and pull only logs from required time period:
        specific_period_logs, additional_period_logs = get_specific_period_logs(archive_name, search_data)


if __name__ == '__main__':
    main()
