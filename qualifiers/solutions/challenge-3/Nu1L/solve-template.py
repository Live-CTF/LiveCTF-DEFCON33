import os
import base64
import frida
import threading
from pwn import *
# context.log_level = "debug"

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
s = remote(HOST, PORT)
s.recvuntil(b"Round ")
s.recvuntil(b"/")
rounds = int(s.recvline().strip())


def run_frida_and_get_password(target_path):
    entered_functions = []
    session_detached = threading.Event()

    def on_message(message, data):
        if message['type'] == 'send':
            payload = message['payload']
            if payload.startswith("Entered function: "):
                func_name = payload[len("Entered function: "):]
                entered_functions.append(func_name)
        elif message['type'] == 'error':
            print(f"[!] {message['stack']}")

    def on_detached(reason, crash):
        session_detached.set()

    pid = frida.spawn([target_path])
    session = frida.attach(pid)
    session.on('detached', on_detached)

    script_code = """
    var moduleName = Process.enumerateModules()[0].name;
    var symbols = Module.enumerateSymbols(moduleName);

    symbols.forEach(function(symbol) {
        if (symbol.type === 'function') {
            try {
                Interceptor.attach(symbol.address, {
                    onEnter: function(args) {
                        if (symbol.name.length >= 9 &&
                            symbol.name[5] === symbol.name[6] &&
                            symbol.name[5] === symbol.name[7] &&
                            symbol.name[5] === symbol.name[8]) {
                            send('Entered function: ' + symbol.name);
                        }
                    }
                });
            } catch (err) {}
        }
    });
    """
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    frida.resume(pid)

    session_detached.wait()

    ret = ''.join([name[5:][0] for name in entered_functions])
    assert ret[:4] == 'PASS'
    return ret[4:].encode()  # 返回 password


def solve(i):
    path = f"./samples/challenge_{i}"
    passBody = run_frida_and_get_password(path)
    return b"PASS{" + passBody + b"}"


def download_challenge(i):
    s.recvuntil(b"Watchme: ")
    b64con = s.recvuntil(b"Password: ", drop=True)
    con = base64.b64decode(b64con)
    with open(f"./samples/challenge_{i}", "wb") as f:
        f.write(con)
    os.system(f"chmod +x ./samples/challenge_{i}")


os.system("rm -rf ./samples")
os.mkdir("./samples")
log.info("Rounds: %d", rounds)
for i in range(10):
    download_challenge(i)
    password = solve(i)
    print(password)
    s.sendline(password)

flag = s.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
print(flag)