from msfcore import MsfClient
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from threading import Thread, Event
from collections import defaultdict
from datetime import datetime, timedelta
from functools import partial
from random import uniform
import configparser
import sys
import time
import os
import logging as log
import re
# TODO: make log level configurable in cfg file
log.basicConfig(level=log.DEBUG)

pbytes = partial(bytes, encoding="utf8")


class StoppableThread(Thread):
    def __init__(self, *args, **kwargs):
        self._stopevent = Event()
        super(self.__class__, self).__init__(*args, **kwargs)

    def stop(self):
        log.debug("Stop called!")
        self._stopevent.set()

    @property
    def stopped(self):
        return self._stopevent.isSet()

    def sleep_for(self, sec):
        self._stopevent.wait(sec)


# TODO: move modules to their own file
class MModule(object):
    def __init__(self, client, cfg=None):
        self.thread = StoppableThread(target=self.main)
        self.thread.daemon = True
        self.client = client
        self.jobid = None
        self.dynamic_opts = defaultdict(lambda: None)
        if cfg:
            if cfg.has_option("general", "name"):
                self.thread.name = cfg["general"]["name"]
            self.cfg = cfg

    def _set_options(self, module):
        for o, v in self.cfg["options"].items():
            self._set_option(module, o, v)

    def _set_option(self, module, key, val):
        # set it if it exists to pymetasploit, otherwise set it as an extra opt
        val = self._parse_value(val)
        key = pbytes(key)
        log.debug("Setting {} to {}".format(key, val))
        opt = [i for i in module.options if i.lower() == key.lower()]
        if any(opt):
            module[opt[0]] = val
        else:
            module._runopts[key] = val

    def _parse_value(self, value):
        if value in self.cfg.BOOLEAN_STATES:
            return self.cfg.BOOLEAN_STATES[value]
        for m in re.finditer(r"(%(\S+?)%)", value):
            value = value.replace(m.group(1), str(self.dynamic_opts.get(m.group(2), m.group(1))))
        func = re.match(r"^@(.*)@$", value)
        if func:
            # yeah I used eval. whatever man
            value = eval(func.group(1))()
        return pbytes(value)

    def _run(self):
        try:
            self.client.lock.acquire()
            module = self.client.rpc.modules.use(*(self._get_modpath()))
            self._set_options(module)
            job = module.execute()
        finally:
            self.client.lock.release()
        if job[b'job_id'] is not None:
            self.jobid = job[b'job_id']
            log.debug("Started job {}".format(job))

    def _get_modpath(self):
        # splits module into type and path
        sp = self.cfg["general"]["module"].split("/")
        return (sp[0], "/".join(sp[1:]))

    def wait_for_job(self):
        while self.jobid:
            try:
                self.client.lock.acquire()
                self.client.rpc.jobs.info(self.jobid)
            except:
                self.jobid = None
            finally:
                self.client.lock.release()

    def start(self):
        self.thread.start()

    def stop(self):
        self.thread.stop()
        self.thread.join()

    def sleep_for(self, sec):
        self.thread.sleep_for(sec)

    @property
    def stopped(self):
        return self.thread.stopped

    def main(self):
        pass


class GlobalModule(MModule):
    def main(self):
        if self.cfg.has_section("globals"):
            try:
                self.client.lock.acquire()
                for g, v in self.cfg["globals"].items():
                    log.debug("setting " + g)
                    if v:
                        self.client.rpc.core.setg(g, v)
                    else:
                        self.client.rpc.core.unsetg(g)
            finally:
                self.client.lock.release()


class SingleModule(MModule):
    def main(self):
        self._run()


class ServiceModule(MModule):
    def main(self):
        svcs = set()
        exclude_port = None
        exclude_host = None
        interval = self.cfg['general'].getint("interval", 5)
        proto = self.cfg["service"].get("protocol", "tcp")
        ports = self.cfg.get("service", "ports")
        new_only = self.cfg["service"].getboolean("new_only", True)
        if self.cfg.has_section("limits"):
            exclude_port = set([int(i) for i in self.cfg["limits"].get("ports", "").split(",") if i])
            exclude_host = set(self.cfg["limits"].get("hosts", "").split(","))
            if exclude_port == {''}:
                exclude_port = None
            if exclude_host == {''}:
                exclude_host = None
        if new_only:
            svcs = self.get_services(proto, ports, True)
        while not self.stopped:
            oldsvcs = svcs
            svcs = self.get_services(proto, ports, True)
            for svc in (svcs - oldsvcs):
                if exclude_host and svc[0].decode() in exclude_host:
                    continue
                if exclude_port and svc[1] in exclude_port:
                    continue
                self.dynamic_opts["HOST"] = svc[0].decode()
                self.dynamic_opts["PORT"] = svc[1]
                self._run()
            self.sleep_for(interval)

    def get_services(self, proto, ports, only_up):
        return set([(x[b'host'], x[b'port']) for x in self.client.db_services(ports=ports, protocol=proto, only_up=only_up)[b'services']])


class IntervalModule(MModule):
    def main(self):
        jitter = self.cfg["general"].getfloat("jitter", 0)
        interval = self.cfg.getint("general", "interval")
        while not self.stopped:
            self._run()
            self.wait_for_job()
            self.sleep_for(interval + (interval * uniform(-jitter, jitter)))


class ModuleManager(object):
    typemap = {"single": SingleModule,
               "service": ServiceModule,
               "interval": IntervalModule,
               "global": GlobalModule}

    def __init__(self, path, config):
        self.client = MsfClient(config)
        self.modules = {}
        self.path = path
        self.last_modify_fire = datetime.now()
        self.read_initial()

        self.eventhandler = PatternMatchingEventHandler(patterns=["*.mpwn"], ignore_directories=True)
        self.eventhandler.on_created = self.on_created
        self.eventhandler.on_modified = self.on_modified
        self.eventhandler.on_deleted = self.on_deleted
        self.eventhandler.on_moved = self.on_moved
        self._dispatch = self.eventhandler.dispatch
        self.eventhandler.dispatch = self.dispatch

        self.observer = Observer()
        self.observer.schedule(self.eventhandler, self.path, recursive=False)
        self.observer.start()
        log.debug("Started scanning {} for module changes".format(self.path))

    def stop(self):
        self.observer.stop()
        self.observer.join()
        self.debug("Stopped module scanner")

    def dispatch(self, event):
        try:
            self._dispatch(event)
            log.debug("Dispatched {} event".format(event.event_type))
        except Exception as e:
            log.error("Excpetion in event dispatcher ({}): {}".format(event.event_type, repr(e)))

    def on_created(self, event):
        # I don't think this check will ever matter
        if event.src_path not in self.modules.keys():
            self.create(event.src_path)

    def on_modified(self, event):
        # Fixes issue #8
        if datetime.now() - self.last_modify_fire < timedelta(seconds=1):
            log.debug("Modified too quickly")
            return
        if event.src_path in self.modules.keys():
            self.on_deleted(event)
        self.create(event.src_path)
        self.last_modify_fire = datetime.now()

    def on_deleted(self, event):
        log.debug("Deleting " + event.src_path)
        if event.src_path in self.modules.keys():
            self.modules[event.src_path].stop()
            del self.modules[event.src_path]

    def on_moved(self, event):
        log.debug(event.src_path + "was moved")
        self.on_deleted(event)
        if event.dest_path.endswith(".mpwn"):
            self.create(event.dest_path)

    def create(self, path):
        log.debug("Creating module at " + path)
        cfg = self.read_module(path)
        if cfg.has_option("general", "disabled") and cfg.getboolean("general", "disabled"):
            log.warning("Module '{}' is disabled".format(path))
            return
        mtype = cfg["general"]["type"]
        if mtype == "global":
            global_list = [i for i in self.modules.values() if isinstance(i, self.typemap[mtype])]
            if any(global_list):
                raise Exception("There is already a global module!")
        if mtype in self.typemap.keys():
            module = self.typemap[mtype](self.client, cfg)
            module.start()
            self.modules[path] = module
        else:
            raise Exception("Module type '{}' was not found".format(mtype))

    def read_initial(self):
        for m in os.listdir(self.path):
            if m.endswith(".mpwn"):
                try:
                    self.create(os.path.join(self.path, m))
                except Exception as e:
                    log.error("Exception in initial module add: " + repr(e))

    @staticmethod
    def read_module(path):
        parser = configparser.ConfigParser(delimiters=("="))
        # make keys case sensitive
        parser.optionxform = str
        parser.read(path)
        return parser


if __name__ == "__main__":
    ms = ModuleManager(sys.argv[2], sys.argv[1])
    while 1:
        time.sleep(5)
