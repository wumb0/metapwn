from metasploit.msfrpc import MsfRpcClient
from metasploit.msfrpc import MsfRpcError
from threading import Lock
import configparser
import yaml

'''
import ssl
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context
'''

class MsfClient(object):

    def __init__(self, config, db_connect = True):
        self.config = configparser.ConfigParser()
        self.config.read(config)
        self._rpc_connect()
        self.lock = Lock()
        if self.config.has_section("globals"):
            for g, v in self.config["globals"].items():
                if v:
                    self.rpc.core.setg(g, v)
                else:
                    self.rpc.core.unsetg(g)
        if self.config.has_section("database"):
            if self.config.has_option("database", "yml") and self.config.has_option("database", "yml_config"):
                with open(self.config.get("database", "yml")) as f:
                    conf = yaml.load(f)
                db_conf = conf[self.config.get("database", "yml_config")]
                for i in ["username", "password", "host", "port", "database"]:
                    # copy yml config values over to config
                    if db_conf.get(i, None):
                        self.config["database"][i] = str(db_conf[i])
            if db_connect:
                self._db_connect()

    def _db_connect(self):
        connected = self.rpc.db.connect(self.config.get("database", "username"),
                                        host=self.config.get("database", "host"),
                                        password=self.config.get("database","password"),
                                        port=self.config.getint("database","port"),
                                        database=self.config.get("database", "database"))
        if not connected:
            raise Exception("Could not connect to the database")

    def _rpc_connect(self):
        self.rpc = MsfRpcClient(self.config.get("rpc", "password"), verify=False,
                                username=self.config.get("rpc", "username"),
                                port=self.config.getint("rpc", "port"),
                                server=self.config.get("rpc", "host"),
                                ssl=self.config.getboolean("rpc", "ssl"))


    def db_hosts(self, **kwargs):
        return self.call('db.hosts', kwargs)

    def db_services(self, **kwargs):
        return self.call('db.services', kwargs)

    def call(self, query, opts):
        try:
            return self.rpc.call(query, opts)
        except MsfRpcError as e:
            # special case where our auth token has expired
            if "token" in str(e).lower():
                self.rpc.sessionid = None
                self.rpc.login(self.config.get("user"), self.config.get("password"))
                return self.rpc.call(query, opts)
            raise MsfRpcError(str(e))

    def start_handler(self, lhost, lport, payload, exitonsession=False, auto_run=None):
        l = self.rpc.modules.use('exploit', 'multi/handler')
        l._runopts['LHOST'] = lhost
        l._runopts['LPORT'] = lport
        l['ExitOnSession'] = exitonsession
        l._runopts['DisablePayloadHandler'] = 'false'
        l._runopts['PAYLOAD'] = payload
        if auto_run:
            l._runopts['AutoRunScript'] = auto_run
        if l.execute()['job_id']:
            print("Handler {} started on {}:{}".format(payload, lhost, lport))
        else:
            print("Handler not started")
