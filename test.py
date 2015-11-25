import pyinotify, subprocess

def change(ev):
    new = ev.name
    print new
    cmd = ['/bin/echo', 'File', ev.pathname, 'changed']
    process = subprocess.Popen(cmd).communicate()

watch = pyinotify.IN_CREATE | pyinotify.IN_MODIFY

delete = pyinotify.IN_DELETE

wm = pyinotify.WatchManager()
wm.add_watch('/root/Documents', watch , change)
notifier = pyinotify.Notifier(wm)
notifier.loop()
