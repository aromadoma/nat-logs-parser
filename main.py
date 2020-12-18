import gzip
import ipaddress
import json
import os
import re
import click
from datetime import date, time, datetime, timedelta

from netmiko import ConnectHandler, file_transfer
from netmiko.ssh_exception import AuthenticationException, NetMikoTimeoutException


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
            click.echo('\u001b[31mWrong username\\password. Please, check credentials.\u001b[0m\n')
            i += 1
        except NetMikoTimeoutException:
            click.echo('\u001b[31mSyslog is unreachable for now. Trying again...\u001b[0m\n')
            i += 1
        else:
            # print('Successfully authenticated.')
            return ssh_connection

    click.echo('\u001b[31mCannot connect to syslog.\u001b[0m')
    return None


def get_timedelta(hours_from_start, minutes_from_start, seconds_from_start):
    user_timedelta = timedelta()
    if hours_from_start:
        user_timedelta += timedelta(hours=hours_from_start)
    if minutes_from_start:
        user_timedelta += timedelta(minutes=minutes_from_start)
    if seconds_from_start:
        user_timedelta += timedelta(seconds=seconds_from_start)

    return user_timedelta


def validate_user_input(user_input, hours_from_start=None, minutes_from_start=None, seconds_from_start=None):
    user_data = {'timedelta': timedelta()}
    if hours_from_start or minutes_from_start or seconds_from_start:
        string = re.search(r'(\S+) (\S+ \S+)', user_input)
        user_data['timedelta'] = get_timedelta(hours_from_start, minutes_from_start, seconds_from_start)
    else:
        string = re.search(r'(\S+) (\S+ \S+) (\S+ \S+)', user_input)
    if string is None:
        click.echo('\u001b[31mPlease, check for entered data.\n\u001b[0m')
        return None

    # Validating ip address:
    try:
        user_data['public_ip'] = ipaddress.ip_address(string.group(1))
    except ValueError:
        click.echo('\u001b[31mERROR: IP address is invalid.\u001b[0m\n')
        return None
    if user_data['public_ip'].is_private:
        click.echo('\u001b[31mERROR: IP address is private.\u001b[0m\n')
        return None

    # Validating start date and time:
    try:
        user_data['start_datetime'] = datetime.fromisoformat(string.group(2))
    except ValueError:
        click.echo('\u001b[31mERROR: Start date or time is invalid.\u001b[0m\n')
        return None
    if user_data['start_datetime'] > datetime.today():
        click.echo('\u001b[31mERROR: Start date or time is in the future.\u001b[0m\n')
        return None

    # Validating stop date and time:
    if user_data['timedelta']:
        user_data['stop_datetime'] = user_data['start_datetime'] + user_data['timedelta']
    else:
        try:
            user_data['stop_datetime'] = datetime.fromisoformat(string.group(3))
        except ValueError:
            click.echo('\u001b[31mERROR: Stop date or time is invalid.\u001b[0m\n')
            return None
    if user_data['stop_datetime'] > datetime.today():
        click.echo('\u001b[31mERROR: Stop date or time is in the future.\u001b[0m\n')
        return None
    elif user_data['stop_datetime'] < user_data['start_datetime']:
        click.echo('\u001b[31mERROR: End time less than start time.\u001b[0m\n')
        return None

    return user_data


def search_for_cgnat_name(ip_address, nat_pools):
    for pool in nat_pools:
        if ip_address in ipaddress.ip_network(pool):
            cgn_hostname = nat_pools[pool]
            click.echo(f'This ip belongs to {pool} pool on {cgn_hostname}.')
            return cgn_hostname
    click.echo('\u001b[31mSORRY. This ip doesn\'t belong to any nat pool. Please, check the ip.\u001b[0m')

    return None


def calculate_archive_date(start_datetime):
    archiving_time = time.fromisoformat('06:25')
    if archiving_time < start_datetime.time() and start_datetime.date() < date.today():
        archive_date = start_datetime.date() + timedelta(days=1)
    elif archiving_time < start_datetime.time() and start_datetime.date() == date.today():
        archive_date = 'TODAY'
    else:
        archive_date = start_datetime.date()

    return archive_date


def string_parsing(f, search_data, decode=True):
    main_period_logs = []
    additional_period_logs = []
    for line in f:
        # There's no need to decode if it's the non-archived logfile from today:
        if decode:
            line = line.decode('utf-8')
        log_datetime = datetime.fromisoformat(re.search(r'^(\S+)\+03:00', line).group(1))
        # Adding logs from main period:
        if search_data['start_datetime'] <= log_datetime <= search_data['stop_datetime'] and str(search_data['public_ip']) in line:
            main_period_logs.append(line.rstrip('\n'))
        # There is need to check additional period, only if stop_datetime - start_datetime < 30 minutes:
        elif search_data['stop_datetime'] - search_data['start_datetime'] < timedelta(minutes=30):
            if search_data['stop_datetime'] <= log_datetime <= search_data['start_datetime'] + timedelta(
                    minutes=30) and str(search_data['public_ip']) in line:
                additional_period_logs.append(line.rstrip('\n'))
        # Stop interations if log is outside the time period:
            elif log_datetime > search_data['start_datetime'] + timedelta(minutes=30):
                break
        elif log_datetime > search_data['stop_datetime']:
            break

    return main_period_logs, additional_period_logs


def get_specific_period_logs(archive_name, search_data):
    path_to_archive = os.path.join(os.path.dirname(__file__), archive_name)
    if '.gz' in archive_name:
        with gzip.open(path_to_archive) as f:
            main_period_logs, additional_period_logs = string_parsing(f, search_data)
    else:
        with open(path_to_archive) as f:
            main_period_logs, additional_period_logs = string_parsing(f, search_data, decode=False)

    return main_period_logs, additional_period_logs


def get_private_ip_list(main_period_logs, additional_period_logs):
    private_ip_list = []
    # Parsing all nat logs in main period of time:
    for log in main_period_logs:
        private_ip = re.search(r': (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ->', log).group(1)
        if private_ip not in private_ip_list:
            private_ip_list.append(private_ip)

    # Parsing only the 'ALLOCATION' and 'RELEASE' logs in additional period of time:
    for log in additional_period_logs:
        if 'PORT_BLOCK_ACTIVE' in log or 'PORT_BLOCK_RELEASE' in log:
            private_ip = re.search(r': (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ->', log).group(1)
            if private_ip not in private_ip_list:
                private_ip_list.append(private_ip)

    return private_ip_list


def handling_request(search_data, parameters):
    # Searching for a CGN hostname:
    cgn_hostname = search_for_cgnat_name(search_data['public_ip'], parameters['nat_pools'])
    # Check if there is no such nat pool:
    if not cgn_hostname:
        return None

    # Calculating the needed archive date:
    archive_date = calculate_archive_date(search_data['start_datetime'])

    # Connecting to syslog server:
    print('Connecting to the syslog server... ')
    ssh_connection = connection_to_server(parameters['ssh_username'], parameters['ssh_password'],
                                          parameters['device_ip'])
    if archive_date != 'TODAY':
        server_output = ssh_connection.send_command(
            f'ls -oh --sort=time --time-style="long-iso" /var/log/{cgn_hostname}/ | grep "{archive_date}"')
        archive_name = re.search(r'secured-pba\.log\.\d+\.gz', server_output).group()
    else:
        archive_name = 'secured-pba.log'

    # Downloading a log file:
    print(f"Path: '/var/log/{cgn_hostname}/{archive_name}', date is {archive_date}.")
    print('Downloading the log file... ')

    dest_file = os.path.join(os.path.dirname(__file__), archive_name)
    if archive_date == 'TODAY':
        # Do not check MD5 and do re-download archive if it's a today log:
        file_transfer(ssh_connection, source_file=archive_name, dest_file=dest_file,
                      file_system=f'/var/log/{cgn_hostname}/', disable_md5=True, direction='get',
                      overwrite_file=True)
    else:
        # CHECK MD5 and DO NOT re-download archive if it's an old one:
        file_transfer(ssh_connection, source_file=archive_name, dest_file=dest_file,
                      file_system=f'/var/log/{cgn_hostname}/', disable_md5=False, direction='get',
                      overwrite_file=False)

    # Opening the log file and pull only logs from required time period:
    print('Parsing the log file...')
    main_period_logs, additional_period_logs = get_specific_period_logs(archive_name, search_data)

    # Creating private ip addresses list:
    private_ip_list = get_private_ip_list(main_period_logs, additional_period_logs)

    # Printing results:
    if len(private_ip_list) == 0:
        print('No addresses have been found.\n')
    else:
        print(f'{len(private_ip_list)} addresses have been found.\n')
        if not parameters['do_not_write']:
            parameters['output_file'].write('********************************************************************\n')
            parameters['output_file'].write(
                f"REQUEST: {search_data['public_ip']} {search_data['start_datetime']} {search_data['stop_datetime']}\n")
            parameters['output_file'].write('********************************************************************\n')
            for private_ip in private_ip_list:
                parameters['output_file'].write(private_ip + '\n')
        if parameters['show_on_screen']:
            for private_ip in private_ip_list:
                print(f'\u001b[32m{private_ip}\u001b[0m')

    return None


@click.command()
@click.option("-f", "user_data_file", type=click.File(), help='File to read requests from')
@click.option("-h", "hours_from_start", type=int, help='Set hours number from start date as time period')
@click.option("-m", 'minutes_from_start', type=int, help='Set minutes number from start date as time period')
@click.option("-s", 'seconds_from_start', type=int, help='Set seconds number from start date as time period')
@click.option("--screen", 'show_on_screen', is_flag=True, help='Display the found private ip list on the screen')
@click.option("--dnw", 'do_not_write', is_flag=True, help='Do not write results to file, show only on the screen')
def main(user_data_file, hours_from_start, minutes_from_start, seconds_from_start, show_on_screen, do_not_write):
    # Path to parameters file:
    parameters_path = os.path.join(os.path.dirname(__file__), 'parameters.json')
    with open(parameters_path) as parameters_file:
        # Loading parameters:
        parameters = json.load(parameters_file)
        # In addition to parameters.json updating the dictionary with keys from console:
        parameters['show_on_screen'] = show_on_screen
        parameters['do_not_write'] = do_not_write
        if do_not_write:
            parameters['show_on_screen'] = True

    # If filename is given:
    if user_data_file:
        click.echo('\nThis script searches private ip addresses which been translated by nat.')
        click.echo('The format should be used: \u001b[32m<public_ip> <start_date> <start_time> <stop_date> '
                   '<stop_time>\u001b[0m')
        click.echo('OR, if you\'re using -h, -m, or -s keys: \u001b[32m<public_ip> <start_date> <start_time>\u001b[0m.')
        click.echo('Search data will be read from file.')

        # Creating a file for outputs:
        if not do_not_write:
            parameters['output_file'] = open(f"request-{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.txt", 'a')

        # User request handling line by line:
        for line in user_data_file:
            line = line.rstrip('\n')
            if re.search(r'^\s*#', line):  # Handling comment lines
                continue
            click.echo(f'\n\u001b[34mREQUEST:\u001b[0m {line}')
            # Checking if data from file are valid:
            search_data = validate_user_input(line, hours_from_start, minutes_from_start, seconds_from_start)
            if search_data:
                handling_request(search_data, parameters)

        # Closing the file for outputs:
        if not do_not_write:
            parameters['output_file'].close()

    else:
        # If filename wasn't given, acting in dialog mode:
        while True:
            shit_counter = 0
            # Waiting for valid user data to be entered:
            click.echo('\nThis script searches private ip addresses which been translated by nat.')
            while True:
                if shit_counter < 5:
                    click.echo('The format should be used: \u001b[32m<public_ip> <start_date> <start_time> <stop_date> '
                               '<stop_time>\u001b[0m')
                else:
                    click.echo('Ah shit, here we go again.')
                click.echo('An example: 11.1.1.1 2020-09-01 19:56 2020-09-01 20:05\n')

                # Entering data and checking if it's valid:
                search_data = validate_user_input(click.prompt('\u001b[34mWhat are we searching?>\u001b[0m', type=str))
                if search_data is not None:
                    break
                else:
                    shit_counter += 1

            # User request handling:
            handling_request(search_data, parameters)


if __name__ == '__main__':
    main()
