from setuptools import setup

setup(
    name='nat-log-parser',
    version='0.1',
    py_modules=['main.py'],
    install_requires=[
        'Click',
        'netmiko',
    ],
    entry_points='''
        [console_scripts]
        nat-log-parser=main:main
    ''',
)