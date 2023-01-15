import argparse
import inspect
import json
import os

from dataclasses import dataclass, asdict
from typing import Optional


_CONFIG_ENV_VAR = 'IPYTHON_BINJA_CONNECTION_CONFIG'


@dataclass(init=True, kw_only=False)
class ConnectionConfig:
    kernel_name: Optional[str] = None
    ip: Optional[str] = None
    stdin_port: Optional[int] = None
    control_port: Optional[int] = None
    hb_port: Optional[int] = None
    signature_scheme: Optional[str] = None
    key: Optional[str] = None
    shell_port: Optional[int] = None
    transport: Optional[str] = None
    iopub_port: Optional[int] = None
    file: Optional[str] = None

    @classmethod
    def from_config_file(cls, file: str):
        with open(file, 'r') as f:
            config = json.load(f)
        return ConnectionConfig(**config)


def read_env_connection_config() -> Optional[ConnectionConfig]:
    args = os.environ.get(_CONFIG_ENV_VAR)
    if args is None:
        return None
    return ConnectionConfig(**json.loads(args))


def get_runner_path() -> str:
    path = inspect.getabsfile(inspect.currentframe())
    assert os.path.exists(path)
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='ipybinja_kernelrun',
        description='command line utility for starting Binary Ninja with jupyter lab support'
    )
    parser.add_argument('binary_ninja', type=str, help='path to binaryninja executable')
    parser.add_argument('--ip', type=str, help='connection IP', required=False)
    parser.add_argument('--stdin', type=int, help='stdin port', required=False)
    parser.add_argument('--control', type=int, help='control port', required=False)
    parser.add_argument('--hb', type=int, help='heartbeat port', required=False)
    parser.add_argument('--Session.signature_scheme', type=str, help='session signature scheme', required=False)
    parser.add_argument('--Session.key', type=str, help='session key', required=False)
    parser.add_argument('--shell', type=int, help='shell port', required=False)
    parser.add_argument('--transport', type=str, help='transport type', required=False)
    parser.add_argument('--iopub', type=int, help='iopub port', required=False)
    parser.add_argument('--f', type=str, help='connection file', required=False)
    args = parser.parse_args()

    assert os.path.exists(args.binary_ninja)

    if args.f is not None and os.path.exists(args.f):
        print(args.f)
        config = ConnectionConfig.from_config_file(args.f)
    else:
        config = ConnectionConfig()

    # Maps arguments passed by VSCode to keys in connection config file
    arg_map = {
        'ip': 'ip',
        'stdin': 'stdin_port',
        'control': 'control_port',
        'hb': 'hb_port',
        'Session.signature_scheme': 'signature_scheme',
        'Session.key': 'key',
        'shell': 'shell_port',
        'transport': 'transport',
        'iopub': 'iopub_port',
        'f': 'file'
    }

    for k, v in arg_map.items():
        arg = getattr(args, k, None)
        if arg is None:
            continue
        # VSCode may wrap strings in format "value" or b"value"
        if isinstance(arg, str):
            if arg.startswith('"'):
                arg = arg[1:-1]
            elif arg.startswith('b"'):
                arg = arg[2:-1]
        setattr(config, v, arg)

    os.execve(args.binary_ninja, [args.binary_ninja], {
        **os.environ,
        _CONFIG_ENV_VAR: json.dumps(asdict(config))
    })
