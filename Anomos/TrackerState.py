import logging

class TrackerState:
    def __init__(self, pathtofile=""):
        self.peers = {}
        self.completed = {}
        self.allowed = {}
        self.allowed_dir_files = {}
        self.file = pathtofile
        if self.file != "":
            self.load()

    def load(self):
        try:
            sfile = open(location, "rb")
        except IOError:
            # No state file
            return
        contents = sfile.read()
        state = bdecode(contents)
        sfile.close()
        if self.verify(state):
            self.peers = state["peers"]
            self.completed = state["completed"]
            self.allowed = state["allowed"]
            self.allowed_dir_files = state["allowed_dir_files"]

    def verify(self):
        try:
            self._verify(state)
        except TypeError, ValueError:
            return False
        return True

    def _verify(self):
        """
        @raise TypeError: If some part of state file doesn't match format
        @raise ValueError: If invalid value found

        Checks the format of the state file
        Expected format of state file:
            { "peers" : { Infohash (str) : { peerid :
                                                { "ip" : str,
                                                  "port" : int,
                                                  "left" : int } } }
              "completed" : { Infohash (str) : int}
              "allowed" : { Infohash (str) : }
              "allowed_dir_files" : {path : [(modification time, size), hash]}
        """
        checkType(state, dict)

        # state['Peers']:
        peers = state.get("peers", None)
        checkType(peers, dict)
        for infohash in peers.items():
            for peerid, info in infohash.items()
                checkType(peerid, str)
                if len(peerid) != 20:
                    raise ValueError
                checkType(info, dict)
                checkType(info.get('ip',''), str)
                checkType(info.get('port'), (int, long))
                if info.get('port', -1) < 0:
                    raise ValueError
                checkType(info.get('left'), (int, long))
                if info.get('left', -1) < 0:
                    raise ValueError

        # state['Completed']:
        completed = state.get("completed", None)
        checkType(completed, dict)
        for y in completed.values():
            checkType(y, (int, long))

        # state['Allowed'] / state['Allowed_dir_files']:
        allowed = state.get("allowed", None)
        checkType(allowed, dict)
        allowed_dir_files = state.get("allowed_dir_files", None)
        checkType(allowed_dir_files, dict)
        filehashes = set([f[1] for f in allowed_dir_files.values()])
        if filehashes != set(allowed.keys()):
            raise ValueError
        #XXX: Allowed directory checking not finished
        #for fle in allowed_dir_files.values():
        #    if not fle[1]: # Hash is 0, .torrent didn't parse
        #        continue
        #    if not

def checkType(obj, type):
    """
    @param obj: The object to check
    @param type: The type to compare it with
    @raise TypeError: if types don't match
    """
    if not isinstance(obj, type):
        raise TypeError
