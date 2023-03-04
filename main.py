import json
import socket
from time import sleep
from loguru import logger
import paramiko
import ipaddress

SSH_PORT = 22
SSH_USERNAME = 'nutanix'
SSH_PASSWORD = ''
SSH_TIMEOUT = 5  # in seconds
OUTPUT_DIR = 'output/'  # output directory for logs and result files
INPUT_FILE = 'prism_ips.txt'
OUTPUT_JSON_FILE_AVAIL = 'result_avail.json'
OUTPUT_JSON_FILE_UPTIME = 'result_uptime.json'
GET_PART_ROWS = 3  # part of rows to get from sorted dictionary, where 3 means 1/3 of rows, 4 means 1/4 of rows, etc.

AVAIL_DICT = {}
UPTIME_DICT = {}

logger.add(f'{OUTPUT_DIR}logs/main.log', format='{time:DD-MM-YY HH:mm:ss} - {level} - {message}',
           level='INFO', rotation='1 week', compression='zip')


class ResultReturn:
    """
    For returning results of operations
    """

    def __init__(self, success=False, data=None, error=None):
        self.success = success
        self.data = data
        self.error = error


def get_svm_ips_from_server(server: str) -> ResultReturn:
    """
    Get SVM IPs from server. Use standard Nutanix command: /usr/local/nutanix/cluster/bin/svmips
    :param server: server IP or hostname
    :return: ResultReturn object
    """
    result = ResultReturn()
    svm_ips = []
    cmd_svm_ips = '/usr/local/nutanix/cluster/bin/svmips'

    logger.info(f'+ Getting SVM IPs for server: {server}')
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(hostname=server, port=SSH_PORT, username=SSH_USERNAME, password=SSH_PASSWORD)
        sleep(2)
    except paramiko.ssh_exception.AuthenticationException:
        logger.error(f'Authentication failed for "{server}", please verify your credentials')
        result.error = f'Authentication failed "{server}", please verify your credentials'
        return result
    except OSError as excpt:
        logger.error(f'Error occurred for "{server}": {excpt}')
        result.error = f'Error occurred for "{server}": {excpt}'
        return result

    # get svm ips
    stdin, stdout, stderr = ssh_client.exec_command(cmd_svm_ips)
    std_out = stdout.readlines()
    out_error = stderr.readlines()
    if not out_error:
        # get svm ips
        ips = std_out[0].strip()
        try:
            # Check if ip is valid
            ips = ips.split()
            for i in ips:
                ipaddress.IPv4Address(i)
                svm_ips.append(i)
        except ValueError:
            logger.error(f' - Error getting svm_ips: {ips}')
            result.error = f'Error getting svm_ips: {ips}'
            return result
        result.success = True
        result.data = svm_ips
    ssh_client.close()
    logger.info(f'  No errors')
    return result


def get_svm_ips_from_file(filepath: str) -> []:
    """
    Load SVM IPs from file to list
    :param filepath:
    :return: list of SVM IPs
    """
    svm_ips = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip() == '':
                continue
            svm_ips.append(line.strip())
    return svm_ips


def get_all_ssh_available_mem(svm_list: []) -> {}:
    """
    Get available memory for all SVMs
    :param svm_list: list of ip addresses for getting available memory
    :return: Dictionary with ip addresses as keys and available memory as values
    """
    cmd = "free | grep '^Mem:' | awk '{print $7}'"
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # svm_dict = {}
    for ip in svm_list:
        ssh_client.close()
        try:
            ssh_client.connect(hostname=ip, port=SSH_PORT, username=SSH_USERNAME,
                               password=SSH_PASSWORD, timeout=SSH_TIMEOUT)
            sleep(0.5)
        except Exception as e:
            AVAIL_DICT[ip] = {
                'available': 0,
                'error': f'Connection failed: {e}'
            }
            logger.error(f' - Connection for {ip} failed: {e}')
            continue
        logger.info(f'+ Getting available memory for {ip}')
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        std_out = stdout.readlines()
        out_error = stderr.readlines()
        if not out_error:
            available = std_out[0].strip()
            AVAIL_DICT[ip] = {
                'available': available,
                'error': 'none'
            }
        else:
            AVAIL_DICT[ip] = {
                'available': 0,
                'error': f'Error exec command "{cmd}"'
            }
            logger.error(f' - Error exec command "{cmd}" on {ip}: {out_error}')
    ssh_client.close()
    logger.info(f'  No errors')
    return AVAIL_DICT


def get_all_ssh_uptime(svm_list: []) -> {}:
    """
    Get uptime for all SVMs
    :param svm_list: List of ip addresses for getting uptime
    :return: Dictionary with ip addresses as keys and uptime as values
    """
    # return exec_allssh_command(server, "uptime | grep days | awk '{print $3}'")
    cmd = "uptime | grep days | awk '{print $3}'"
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # svm_dict = {}
    for ip in svm_list:
        ssh_client.close()
        try:
            ssh_client.connect(hostname=ip, port=SSH_PORT, username=SSH_USERNAME,
                               password=SSH_PASSWORD, timeout=SSH_TIMEOUT)
            sleep(0.5)
        except Exception as e:
            UPTIME_DICT[ip] = {
                'uptime': 0,
                'error': f'Connection failed: {e}'
            }
            logger.error(f' - Connection for {ip} failed: {e}')
            continue
        logger.info(f'+ Getting uptime for {ip}')
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        std_out = stdout.readlines()
        out_error = stderr.readlines()
        if not out_error:
            uptime = std_out[0].strip()
            UPTIME_DICT[ip] = {
                'uptime': uptime,
                'error': 'none'
            }
        else:
            UPTIME_DICT[ip] = {
                'uptime': 0,
                'error': f'Error exec command "{cmd}"'
            }
            logger.error(f' - Error exec command "{cmd}" for {ip}')
    ssh_client.close()
    logger.info(f'  No errors')
    return UPTIME_DICT


def sort_dict_by_value(dict_to_sort: {}, key_name: str, reverse_sort: True) -> {}:
    """
    Sort dict by available memory and uptime. Available memory converted from KB to GB
    :param reverse_sort:
    :param key_name:
    :param dict_to_sort:
    :return: sorted dict
    """
    srt_dict = dict(sorted(dict_to_sort.items(), key=lambda item: (float(item[1][key_name])), reverse=reverse_sort))
    return srt_dict


def save_dict_to_json(dict_to_save: {}, filepath: str):
    """
    Save dictionary to json file
    :param dict_to_save: What to save
    :param filepath: Where to save
    :return: Nothing
    """
    with open(filepath, 'w') as f:
        json.dump(dict_to_save, f, indent=4)
        logger.info(f'+ Result saved to {filepath}')


def get_first_rows(data_dict: {}, divider: int) -> {}:
    """
    Get first rows from dictionary
    :param data_dict: Source dictionary
    :param divider: What part of dictionary to get
    :return: Dictionary with filtered rows
    """
    rows_count = divmod(len(data_dict), divider)[0]  # Getting an integer from division
    sliced_dict = {k: v for i, (k, v) in enumerate(data_dict.items()) if i < rows_count}
    return sliced_dict


def resolve_ip_to_fqdn(ip_address):
    """
    Resolve IP address to FQDN. If cannot resolve, then return IP address
    :param ip_address:
    :return: FQDN or IP address
    """
    try:
        fqdn = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        logger.error(f' - Cannot resolve {ip_address} to FQDN. Keep IP address')
        fqdn = ip_address
    return fqdn


def print_dicts(uptime_dict, avail_dict):
    # Print table header
    print("{:<32}{:<20}".format("Uptime", "Free"))

    # Get keys from first dictionaries
    keys = list(uptime_dict.keys())

    # Iterate over keys and print values from both dictionaries. Second dictionary left origin ordered.
    for i, key in enumerate(keys):
        # Get values from both dictionaries
        # TODO: Check for index out of range!!!
        key2 = list(avail_dict.keys())[i]

        value1 = uptime_dict[key]
        value2 = avail_dict[key2]

        # Print values
        avail_gb = round(float(value2["available"]) / 1024 / 1024, 2)
        print("{:<2d}. {:<20} {:>3} up {:<20} {:<3} GB".format(i + 1, key, value1["uptime"],
                                                               keys[(i + 1) % len(keys)], avail_gb))


def main():
    prism_addresses = get_svm_ips_from_file(INPUT_FILE)
    for prism_address in prism_addresses:
        svm_ips = get_svm_ips_from_server(prism_address)
        if svm_ips.success:
            svm_ips = svm_ips.data
            # Get available memory
            get_all_ssh_available_mem(svm_ips)
            # Get uptime
            get_all_ssh_uptime(svm_ips)
        else:
            logger.error(f'Error get SVM IPs from {prism_address}: {svm_ips.error}')
    if not AVAIL_DICT or not UPTIME_DICT:
        logger.error('Error get available memory or uptime')
        return
    # Get sorted dicts
    sorted_avail = sort_dict_by_value(AVAIL_DICT, key_name='available', reverse_sort=False)
    # Try to resolve IP to FQDN
    sorted_avail = {resolve_ip_to_fqdn(k): v for k, v in sorted_avail.items()}
    # Save sorted dicts to json files
    save_dict_to_json(sorted_avail, f'{OUTPUT_DIR}{OUTPUT_JSON_FILE_AVAIL}')
    # ==================================================
    # Uncomment next line to get part of sorted dicts
    # sorted_avail = get_first_rows(sorted_avail, GET_PART_ROWS)
    # ==================================================

    if not UPTIME_DICT and not AVAIL_DICT:
        logger.error('Error get uptime and available memory')
        return

    sorted_uptime = sort_dict_by_value(UPTIME_DICT, key_name='uptime', reverse_sort=True)
    # Try to resolve IP to FQDN
    sorted_uptime = {resolve_ip_to_fqdn(k): v for k, v in sorted_uptime.items()}
    # Save sorted dicts to json files
    save_dict_to_json(sorted_uptime, f'{OUTPUT_DIR}{OUTPUT_JSON_FILE_UPTIME}')
    # ==================================================
    # Uncomment next line to get part of sorted dicts
    # sorted_uptime = get_first_rows(sorted_uptime, GET_PART_ROWS)
    # ==================================================

    # Print sorted dicts
    print_dicts(sorted_uptime, sorted_avail)


if __name__ == '__main__':
    try:
        logger.info('===== Start collecting data =====')
        main()
    except Exception as e:
        logger.error(f'Error: {e}')
        raise e
    logger.info('===== End collecting data =====')
