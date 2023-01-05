import subprocess
import os
import re
from collections import namedtuple
import win32gui, win32api, win32con, win32file, pywintypes
from update_security_group import UpdateExecutor, LOG_FILE, TAG


PID_FILE = os.path.join(win32api.GetTempPath(), re.sub(r'\.\w+$', '.pid', os.path.basename(__file__)))

try:
    hPidFile = win32file.CreateFile(
        PID_FILE,
        win32con.GENERIC_WRITE | win32con.GENERIC_READ,
        win32con.FILE_SHARE_READ,
        None,
        win32con.CREATE_ALWAYS,
        win32con.FILE_ATTRIBUTE_NORMAL,
        None
    )
except pywintypes.error as e:
    if e.winerror == 32:
        hPidFile = win32file.INVALID_HANDLE_VALUE
    else:
        raise e

if hPidFile == win32file.INVALID_HANDLE_VALUE:
    win32gui.MessageBox(
        None,
        "监控任务已经在运行中",
        "安全组监控器",
        win32con.MB_ICONWARNING
    )
    exit(1)

win32file.WriteFile(hPidFile, str(os.getpid()).encode('ascii'), None)

NOTIFY_ICON = win32gui.LoadImage(
        None,
        os.path.join(os.path.realpath(os.path.dirname(__file__)), "aliyun-256.ico"),
        win32con.IMAGE_ICON,
        win32con.LR_DEFAULTSIZE,
        win32con.LR_DEFAULTSIZE,
        win32con.LR_DEFAULTCOLOR | win32con.LR_LOADFROMFILE
    )

NOTIFY_MESSAGE_ID = win32con.WM_USER + 1

ID_TRAY_RUN_NOW = 0x1001
ID_TRAY_VIEW_LOG = 0x1002
ID_TRAY_EXIT = 0x1003

IDT_SCHEDULE_TIMER = 0x1001

NotifycationData = namedtuple("NOTIFYCATIONDATA",
        ('hWnd', 'uId', 'uFlags', 'uCallbackMessage', 'hIcon', 'tip', 'info', 'uTimeout', 'infoTitle', 'uInfoFlags'),
        rename=False,
        defaults=(None, 0, 0, 0, None, "", "", 0, "", 0),
    )

def make_notify(
        hWnd=None,
        tip=f"ECS安全组监控中，目标描述“{TAG}”",
        info=None,
        uTimeout=0):
    uInfoFlags = 0
    uFlags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
    if info is None:
        info = ""
    else:
        uFlags |= win32gui.NIF_INFO
        uTimeout = 5
    return NotifycationData(
            hWnd=hWnd,
            uId=0,
            uFlags=uFlags,
            uCallbackMessage=NOTIFY_MESSAGE_ID,
            hIcon=NOTIFY_ICON,
            tip=tip,
            info=info,
            uTimeout=uTimeout,
            uInfoFlags=uInfoFlags
        )

hMenu = win32gui.CreatePopupMenu()
win32gui.AppendMenu(hMenu, win32con.MF_STRING, ID_TRAY_RUN_NOW, "立即更新")
win32gui.AppendMenu(hMenu, win32con.MF_STRING, ID_TRAY_VIEW_LOG, "查看运行日志")
win32gui.AppendMenu(hMenu, win32con.MF_STRING, ID_TRAY_EXIT, "退出")

update_executor = UpdateExecutor()

def notify_handler(hWnd, msg, wParam, lParam):
    def quit_app():
        update_executor.stop()
        win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, make_notify(hWnd, tip="结束ECS安全组更新"))
        win32gui.PostQuitMessage(0)
        win32file.CloseHandle(hPidFile)
    if msg == NOTIFY_MESSAGE_ID:
        if lParam == win32con.WM_RBUTTONUP:
            cx, cy = win32gui.GetCursorPos()
            win32gui.SetForegroundWindow(hWnd)
            win32gui.TrackPopupMenu(hMenu, 0, cx, cy, 0, hWnd, None)
            return True
        elif lParam == win32con.WM_LBUTTONDBLCLK:
            update_executor.execute_async()
            return True
    elif msg == win32con.WM_COMMAND:
        wmId = win32api.LOWORD(wParam)
        wmEvt = win32api.HIWORD(wParam)
        if wmId == ID_TRAY_RUN_NOW:
            update_executor.execute_async()
            return True
        elif wmId == ID_TRAY_VIEW_LOG:
            subprocess.run(['explorer', LOG_FILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif wmId == ID_TRAY_EXIT:
            quit_app()
            return True
    return win32gui.DefWindowProc(hWnd, msg, wParam, lParam)

wc = win32gui.WNDCLASS()
wc.hInstance = win32gui.GetModuleHandle(None)
wc.lpszClassName = "UpdateECSSecurityGroup"
wc.lpfnWndProc = notify_handler
wcls = win32gui.RegisterClass(wc)
hWnd = win32gui.CreateWindow(
        "UpdateECSSecurityGroup",
        "ECS安全组更新",
        win32con.WS_OVERLAPPEDWINDOW,
        win32con.CW_USEDEFAULT,
        win32con.CW_USEDEFAULT,
        win32con.CW_USEDEFAULT,
        win32con.CW_USEDEFAULT,
        None,
        None,
        None,
        None
    )

def update_executor_monitor(err, n_delete=None, n_add=None):
    if err == UpdateExecutor.MSG_UPDATE_SUCCESS:
        if n_delete != 0 or n_add != 0:
            info_msg = "ECS安全组进行了更新"
            if n_delete != 0:
                info_msg += f"，删除了{n_delete}条规则"
            if n_add != 0:
                info_msg += f"，添加了{n_add}条规则"
            win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, make_notify(hWnd, info=info_msg))
        else:
            win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, make_notify(hWnd))
    elif err == UpdateExecutor.MSG_UPDATE_FAILED:
        win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, make_notify(hWnd, info="ECS安全组更新失败"))
    elif err == UpdateExecutor.MSG_UPDATE_START:
        win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, make_notify(hWnd, tip=f"正在执行ECS安全组更新，目标描述“{TAG}”"))
    elif err == UpdateExecutor.MSG_UPDATE_BUSY:
        win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, make_notify(hWnd))

update_executor.monitor = update_executor_monitor

win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, make_notify(hWnd))

update_executor.start_schedule()

win32gui.PumpMessages()

# import code; code.interact("", local=locals())

