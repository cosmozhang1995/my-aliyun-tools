import requests
import json
import logging
import re
import threading
import traceback
import datetime
import os
import configparser
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import RpcRequest
from aliyunsdkecs.request.v20140526.DescribeSecurityGroupAttributeRequest import DescribeSecurityGroupAttributeRequest
from aliyunsdkecs.request.v20140526.AuthorizeSecurityGroupRequest import AuthorizeSecurityGroupRequest
from aliyunsdkecs.request.v20140526.RevokeSecurityGroupRequest import RevokeSecurityGroupRequest

CONFIG_FILE = os.path.realpath(re.sub(r'\.\w+$', '.conf', __file__))
CONFIG = configparser.ConfigParser()
CONFIG.read(CONFIG_FILE, encoding='utf-8')
ACCESS_ID = CONFIG.get('aliyun', 'access_id')
ACCESS_SECRET = CONFIG.get('aliyun', 'access_secret')
REGION_ID = CONFIG.get('aliyun', 'region_id')
SG_ID = CONFIG.get('aliyun', 'security_group_id')
TAG = CONFIG.get('aliyun', 'tag')
PORTS = [port for port in re.split(r'[\s\,]+', CONFIG.get('aliyun', 'ports')) if port]

LOG_FILE = CONFIG.get('app', 'log_file', )
if not LOG_FILE:
    LOG_FILE = os.path.realpath(re.sub(r'\.\w+$', '.log', __file__))

SCHEDULE = CONFIG.get('app', 'schedule').strip()

logger = logging.getLogger('main')
logger.setLevel(logging.DEBUG)
logger.handlers.clear()
logger_handler_console = logging.StreamHandler()
logger_handler_console.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
logger.addHandler(logger_handler_console)
logger_handler_file = logging.FileHandler(LOG_FILE)
logger_handler_file.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
logger.addHandler(logger_handler_file)

def send_request(client: AcsClient, request: RpcRequest):
    request.set_accept_format('json')
    response = client.do_action(request)
    response = json.loads(response)
    return response

def query_local_ip():
    my_ip = requests.get('https://api.ipify.org?format=json').json()['ip']
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', my_ip) is None:
        raise ValueError("invalid local IP: {}".format(my_ip))
    return my_ip

def update_sg_rule():
    logger.info('Running ECS security group updater')
    client = AcsClient(ACCESS_ID, ACCESS_SECRET, REGION_ID)
    my_ip = query_local_ip()
    req = DescribeSecurityGroupAttributeRequest()
    req.set_SecurityGroupId(SG_ID)
    res = send_request(client, req)
    to_add_rules = [{
        'NicType': 'intranet',
        'Direction': 'ingrees',
        'Policy': 'Accept',
        'Priority': 1,
        'GressFlow': 'in',
        'IpProtocol': 'TCP',
        'SourceCidrIp': my_ip,
        'PortRange': port,
        'Description': TAG
    } for port in PORTS]
    to_delete_rules = []
    for permission in res['Permissions']['Permission']:
        if permission['Description'] == TAG and permission['PortRange'] in PORTS:
            if permission['SourceCidrIp'] == my_ip:
                to_add_rules = [
                    rule for rule in to_add_rules \
                    if rule['PortRange'] != permission['PortRange']
                ]
            else:
                to_delete_rules.append({
                    'IpProtocol': permission['IpProtocol'],
                    'SourceCidrIp': permission['SourceCidrIp'],
                    'PortRange': permission['PortRange'],
                    'Description': permission['Description']
                })
    if len(to_delete_rules) != 0:
        req = RevokeSecurityGroupRequest()
        req.set_SecurityGroupId(SG_ID)
        req.set_Permissions(to_delete_rules)
        send_request(client, req)
        for rule in to_delete_rules:
            logger.info('Remove rule: SourceCidrIp={} PortRange={} Description={}'.format(rule['SourceCidrIp'], rule['PortRange'], rule['Description']))
    if len(to_add_rules) != 0:
        req = AuthorizeSecurityGroupRequest()
        req.set_SecurityGroupId(SG_ID)
        req.set_Permissions(to_add_rules)
        send_request(client, req)
        for rule in to_add_rules:
            logger.info('Add rule: SourceCidrIp={} PortRange={} Description={}'.format(rule['SourceCidrIp'], rule['PortRange'], rule['Description']))
    return len(to_delete_rules), len(to_add_rules)


class UpdateExecutor:
    MSG_UPDATE_START = 0
    MSG_UPDATE_SUCCESS = 1
    MSG_UPDATE_FAILED = 2
    MSG_UPDATE_FINISHED = 3
    MSG_UPDATE_BUSY = 9
    MSG_SCHEDULE_START = 11
    MSG_SCHEDULE_STOP = 12

    SCHEDULE_METHOD_NONE = "none"
    SCHEDULE_METHOD_HOURLY = "hourly"
    SCHEDULE_METHOD_DAILY = "daily"
    
    def __init__(self, monitor=None):
        self.stop_flag = True
        self.running = False
        if monitor is None:
            def _empty_monitor(err, *args, **kwargs):
                pass
            monitor = _empty_monitor
        self.monitor = monitor
        self.lock = threading.Lock()
        self.main_thread: threading.Thread = None
        self.main_thread_lock = threading.Lock()
        self.schedule_thread: threading.Thread = None
        self.schedule_timer = threading.Event()
        self.schedule_thread_lock = threading.Lock()
        self.is_executing = False
        self.is_scheduling = False
        self.next_schedule = datetime.datetime.now()

    def execute_async(self):
        self.main_thread_lock.acquire()
        if self.main_thread is not None and self.main_thread.is_alive():
            self.main_thread_lock.release()
            self.monitor(UpdateExecutor.MSG_UPDATE_BUSY)
            return
        self.main_thread = threading.Thread(target=UpdateExecutor.execute_sync, args=(self,))
        self.main_thread.start()
        self.main_thread_lock.release()
    
    def execute_sync(self):
        self.lock.acquire()
        if self.running:
            self.lock.release()
            self.monitor(UpdateExecutor.MSG_UPDATE_BUSY)
            return
        self.running = True
        self.is_executing = True
        self.lock.release()
        self.monitor(UpdateExecutor.MSG_UPDATE_START)
        try:
            n_delete, n_add = update_sg_rule()
            self.monitor(UpdateExecutor.MSG_UPDATE_SUCCESS, n_delete=n_delete, n_add=n_add)
        except Exception as e:
            logging.error("Update failed:\n" + traceback.format_exc())
            self.monitor(UpdateExecutor.MSG_UPDATE_FAILED)
        self.is_executing = False
        self.lock.acquire()
        self.running = False
        self.lock.release()
        self.monitor(UpdateExecutor.MSG_UPDATE_FINISHED)

    def start_schedule(self):
        self.schedule_thread_lock.acquire()
        if self.schedule_thread is not None and self.schedule_thread.is_alive():
            self.schedule_thread_lock.release()
            raise RuntimeError("schedule start twice")
        self.schedule_thread = threading.Thread(target=UpdateExecutor._schedule_exec, args=(self,))
        self.schedule_timer.clear()
        self.schedule_thread.start()
        self.schedule_thread_lock.release()

    def stop_schedule(self):
        self.schedule_thread_lock.acquire()
        self.schedule_timer.set()
        thread = self.schedule_thread
        self.schedule_thread_lock.release()
        if thread is not None:
            thread.join()

    def _schedule_exec(self):
        if SCHEDULE:
            schedule = [s.strip() for s in SCHEDULE.split('+')]
            if len(schedule) > 2:
                raise ValueError(f"illegal schedule [{SCHEDULE}]")
            schedule_method = schedule[0]
            if schedule_method == UpdateExecutor.SCHEDULE_METHOD_NONE and len(schedule) > 1:
                raise ValueError(f"illegal schedule [{SCHEDULE}]")
            if len(schedule) == 2:
                sd_match = re.match(r'^\s*((?P<day>\d+)\s*(d|day|days))?\s*((?P<hour>\d+)\s*(h|hour|hours))?\s*((?P<minute>\d+)\s*(m|min|minute|minutes))?\s*((?P<second>\d+)\s*(s|sec|second|seconds))?\s*$', schedule[1])
                if sd_match is None:
                    raise ValueError(f"illegal schedule [{SCHEDULE}]")
                sd_day = int(sd_match.group('day') or '0')
                sd_hour = int(sd_match.group('hour') or '0')
                sd_min = int(sd_match.group('minute') or '0')
                sd_sec = int(sd_match.group('second') or '0')
                if sd_day >= 7:
                    raise ValueError(f"illegal schedule [{SCHEDULE}]: delaying more than 7 days is not allowed")
                if sd_hour >= 24 or sd_min >= 60 or sd_sec >= 60:
                    raise ValueError(f"illegal schedule [{SCHEDULE}]")
                schedule_delay = datetime.timedelta(days=sd_day) \
                               + datetime.timedelta(hours=sd_hour) \
                               + datetime.timedelta(minutes=sd_min) \
                               + datetime.timedelta(seconds=sd_sec)
        else:
            schedule_method = UpdateExecutor.SCHEDULE_METHOD_NONE
            schedule_delay = datetime.timedelta()
        if schedule_method == UpdateExecutor.SCHEDULE_METHOD_NONE:
            if schedule_delay.total_seconds() != 0:
                raise ValueError(f"illegal schedule [{SCHEDULE}]: no delay is allowed for none schedule")
        elif schedule_method == UpdateExecutor.SCHEDULE_METHOD_HOURLY:
            if schedule_delay.total_seconds() >= 3600:
                raise ValueError(f"illegal schedule [{SCHEDULE}]: delaying more than 1 hour is not allowed for hourly schedule")
        elif schedule_method == UpdateExecutor.SCHEDULE_METHOD_DAILY:
            if schedule_delay.total_seconds() >= 3600 * 24:
                raise ValueError(f"illegal schedule [{SCHEDULE}]: delaying more than 1 day is not allowed for daily schedule")
        else:
            raise ValueError(f"illegal schedule [{SCHEDULE}]")
        if schedule_method == UpdateExecutor.SCHEDULE_METHOD_NONE:
            return
        now = datetime.datetime.now()
        if schedule_method == UpdateExecutor.SCHEDULE_METHOD_HOURLY:
            now = datetime.datetime(year=now.year, month=now.month, day=now.day, hour=now.hour) + schedule_delay
            dt = datetime.timedelta(hours=1)
        elif schedule_method == UpdateExecutor.SCHEDULE_METHOD_DAILY:
            now = datetime.datetime(year=now.year, month=now.month, day=now.day) + schedule_delay
            dt = datetime.timedelta(days=1)
        else:
            raise ValueError(f"illegal schedule [{SCHEDULE}]")
        if now <= datetime.datetime.now():
            next = now + dt
        else:
            next = now
        self.is_scheduling = True
        self.monitor(UpdateExecutor.MSG_SCHEDULE_START)
        while not self.schedule_timer.is_set():
            wt = (next - datetime.datetime.now()).total_seconds()
            if wt > 0:
                if self.schedule_timer.wait(wt):
                    break
            self.execute_async()
            next = next + dt
        self.is_scheduling = False
        self.monitor(UpdateExecutor.MSG_SCHEDULE_STOP)

    def stop(self):
        self.stop_schedule()
        self.main_thread_lock.acquire()
        thread = self.main_thread
        self.main_thread_lock.release()
        if thread is not None:
            thread.join()

