# IPyBinja

IPyBinja brings the full features provided by [IPython](https://ipython.org) interactive shell to [Binary Ninja](https://binary.ninja). 

https://user-images.githubusercontent.com/75971916/207032716-0cfb7e31-fb9e-4e7f-bb8c-e8f77df24bf6.mp4


## Why use IPyBinja?

1. Provides features like syntax highlighting, magic commands and embedded figures which are not present in the Binary Ninja inbuilt Python console.
2. Includes all features of inbuilt Python console like magic variables, auto-completion, history, etc.
3. Can link the Python interpreter instance inside Binary Ninja to a Jupyter notebook / lab.
4. Will not freeze the UI while scripts are running.
5. Running scripts can be interrupted with `Ctrl+C` key combination.


## Installation

1. Clone this repository to the plugins directory of your Binary Ninja installation.  Example for macOS:
```shell
cd ~/Library/Application\ Support/Binary\ Ninja/plugins
git clone https://github.com/skr0x1c0/ipybinja.git
```

2. If you have configured Binary Ninja to use a python virtual environment, you will need to activate the virtual environment before continuing.

```shell
source ~/.venv_binja/bin/activate
```

3. Install the required dependencies:

```shell
cd ipybinja
pip install -r requirements.txt
```

That's it!  You should now be able to use the IPython console widget in Binary Ninja.

## Usage

1. For a list of additional magic commands provided by the plugin see [this document](./docs/magic_commands.md)
2. For using Jupyter lab / notebook with Binary Ninja see [this document](./docs/notebook.md)

## Credits

This plugin is based on [ipyida](https://github.com/eset/ipyida) IDA Pro plugin.


## License

This plugin is released under an [MIT license](./LICENSE).
