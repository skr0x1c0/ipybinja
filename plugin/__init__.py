from ipybinja import *


if not isinstance(asyncio.get_event_loop(), qasync.QEventLoop):
    qapp = QApplication.instance()
    loop = qasync.QEventLoop(qapp, already_running=True)
    asyncio.set_event_loop(loop)

GlobalArea.addWidget(
    lambda _: IPythonWidget('IPython Console')
)

PluginCommand.register(
    'IPyBinja\\Install Jupyter Kernel',
    'Install jupyter kernel configuration for Binary Ninja',
    lambda _: InstallKernelSpecTask().start(),
    lambda _: True
)
