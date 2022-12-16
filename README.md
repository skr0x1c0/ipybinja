# Binja IPython

Binja IPython brings the full features provided by [IPython](https://ipython.org) interactive shell to [Binary Ninja](https://binary.ninja). 

https://user-images.githubusercontent.com/75971916/207032716-0cfb7e31-fb9e-4e7f-bb8c-e8f77df24bf6.mp4


## Why use Binja IPython?

1. Provides features like syntax highlighting, magic commands and embedded figures which are not present in the Binary Ninja inbuilt Python console.
2. Includes all features of inbuilt Python console like magic variables, auto-completion, history, etc.
3. Can link the Python interpreter instance inside Binary Ninja to a Jupyter notebook / lab.
4. Will not freeze the UI while scripts are running.
5. Running scripts can be interrupted with `Ctrl+C` key combination.


## Installation

This plugin is available on Binary Ninja plugin manager. But if you prefer to install from source, follow these steps:-

1. Open command pallete inside Binary Ninja and click "Install python3 module"
2. Copy and paste the contents from `requirements.txt` in this repo to the popup window and click install
3. Clone this repository to Binary Ninja user plugins directory
4. Restart Binary Ninja


## Usage

1. For a list of additional magic commands provided by the plugin see [this document](./docs/magic_commands.md)
2. For using Jupyter lab / notebook with Binary Ninja see [this document](./docs/notebook.md)


## Credits

This plugin is based on [ipyida](https://github.com/eset/ipyida) IDA Pro plugin.


## License

This plugin is released under an [MIT license](./LICENSE).
