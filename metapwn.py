from msfcore import MsfClient
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import configparser
from threading import Thread, Event
import sys
import time
import os
import logging as log
# TODO: make log level configurable in cfg file
log.basicConfig(level=log.DEBUG)


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
        log.debug("Running module init for " + cfg["general"]["module"])
        if cfg:
            if cfg.has_option("general", "name"):
                self.thread.name = cfg["general"]["name"]
            self.cfg = cfg

    def _set_options(self, module):
        for o, v in self.cfg["options"].items():
            # set it if it exists to pymetasploit, otherwise set it as an extra opt
            opt = [i for i in module.options if i.lower() == o.lower()]
            if any(opt):
                module[opt[0]] = v
            else:
                module._runopts[o] = v

    def _run(self):
        try:
            self.client.lock.acquire()
            module = self.client.rpc.modules.use(*(self._get_modpath()))
            self._set_options(module)
            job = module.execute()['job_id']
        finally:
            self.client.lock.release()
        if job is not None:
            log.debug("Started job {}".format(job))

    def _get_modpath(self):
        # splits module into type and path
        sp = self.cfg["general"]["module"].split("/")
        return (sp[0], "/".join(sp[1:]))

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


class SingleModule(MModule):
    def main(self):
        self._run()


class ServiceModule(MModule):
    pass


class IntervalModule(MModule):
    def main(self):
        while not self.stopped:
            self._run()
            self.sleep_for(self.cfg.getint("general", "interval"))

class ModuleManager(object):
    typemap = {"single": SingleModule,
               "service": ServiceModule,
               "interval": IntervalModule}

    def __init__(self, path, config):
        self.client = MsfClient(config)
        self.modules = {}
        self.path = path
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
        except Exception as e:
            log.error("Excpetion in event dispatcher ({}): {}".format(event.event_type, repr(e)))

    def on_created(self, event):
        # I don't think this check will ever matter
        if event.src_path not in self.modules.keys():
            self.create(event.src_path)

    def on_modified(self, event):
        if event.src_path in self.modules.keys():
            self.on_deleted(event)
        self.create(event.src_path)

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
        parser = configparser.ConfigParser()
        # make keys case sensitive
        parser.optionxform = str
        parser.read(path)
        return parser


if __name__ == "__main__":
    ms = ModuleManager(sys.argv[2], sys.argv[1])
    while 1:
        print(ms.modules)
        time.sleep(5)
