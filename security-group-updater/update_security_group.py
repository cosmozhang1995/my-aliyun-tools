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
cp = configparser.ConfigParser()
cp.read(CONFIG_FILE, encoding='utf-8')
ACCESS_ID = cp.get('aliyun', 'access_id')
ACCESS_SECRET = cp.get('aliyun', 'access_secret')
REGION_ID = cp.get('aliyun', 'region_id')
SG_ID = cp.get('aliyun', 'security_group_id')
TAG = cp.get('aliyun', 'tag')
PORTS = [port for port in re.split(r'[\s\,]+', cp.get('aliyun', 'ports')) if port]

LOG_FILE = cp.get('app', 'log_file', )
if not LOG_FILE:
    LOG_FILE = os.path.realpath(re.sub(r'\.\w+$', '.log', __file__))

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
    MSG_UPDATE_BUSY = 3
    
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
        self.lock.release()
        self.monitor(UpdateExecutor.MSG_UPDATE_START)
        try:
            n_delete, n_add = update_sg_rule()
            self.monitor(UpdateExecutor.MSG_UPDATE_SUCCESS, n_delete=n_delete, n_add=n_add)
        except Exception as e:
            logging.error("Update failed:\n" + traceback.format_exc())
            self.monitor(UpdateExecutor.MSG_UPDATE_FAILED)
        self.lock.acquire()
        self.running = False
        self.lock.release()

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
        now = datetime.datetime.now()
        now = datetime.datetime(year=now.year, month=now.month, day=now.day, hour=now.hour)
        while not self.schedule_timer.is_set():
            next = now + datetime.timedelta(hours=1)
            wt = (next - datetime.datetime.now()).total_seconds()
            if wt > 0:
                if self.schedule_timer.wait(wt):
                    break
            self.execute_async()
            now = next

    def stop(self):
        self.stop_schedule()
        self.main_thread_lock.acquire()
        thread = self.main_thread
        self.main_thread_lock.release()
        if thread is not None:
            thread.join()

