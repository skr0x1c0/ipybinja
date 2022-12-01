import argparse
import inspect
import os


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
    parser.add_argument('connection_file', type=str, help='path to the connection file')
    args = parser.parse_args()

    assert os.path.exists(args.binary_ninja)
    os.execve(args.binary_ninja, [args.binary_ninja], {
        **os.environ,
        'IPYTHON_BINJA_CONNECTION_FILE': args.connection_file
    })
