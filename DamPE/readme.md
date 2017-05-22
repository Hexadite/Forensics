# DamPE - Disk and Memory PE Comparison

[![Hexadite](https://www.hexadite.com/wp-content/uploads/logo-without-tag.png)](https://hexadite.com)

DamPE is a script to demonstrate the consept of detecting suspicious modules in memory by comparing them to their file on disk.

# How It Works

  - Iterates over the currently running processes of the system
  - For each process, iterates over it's loaded modules
  - Each module is compared with the file on disk that suppose to be loaded to that memory address
  - The comperison is made by comparing all fields of all headers of the PE file format
  - If some of the Interesting fields has beed changed, the module's memory content is considered suspicious


### Dependencies

* [Python](https://www.python.org/) - Python 2.7.
  *  On 64 bit windows, it is recommanded to use 64 bit version of Python.
* [pefile](https://pypi.python.org/pypi/pefile/) - Python PE parsing module
* [tqdm](https://pypi.python.org/pypi/tqdm) - Python progress meter module


### Usage

##### flags

The scripts support several flags to custom his operation:

| Name | Short | Description |
| ------ | ------ | ------ |
| \-\-all | -a | Specify whether to show information about all of the modules instead of the suspicious ones only (optional) |
| \-\-group_by_processes | -g | Specify whether to group the information by processes or not (optional) |
| \-\-output=<file> | -o <file> | Output file (Default: "DamPE-result.json") |

##### Example
```batch
$ DamPE.py --group_by_processes --output=DamPE-results.json
```

Source
----
[DamPE](https://hexadite.com/DamPE/)

License
----
[GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.en.html)
