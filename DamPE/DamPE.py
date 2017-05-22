"""
DamPE

DamPE is a script to demonstrate the consept of detecting suspicious modules in memory by comparing them to their file on disk.

How It Works:
    * Iterates over the currently running processes of the system
    * For each process, iterates over it's loaded modules
    * Each module is compared with the file on disk that suppose to be loaded to that memory address
    * The comperison is made by comparing all fields of all headers of the PE file format
    * If some of the Interesting fields has beed changed, the module's memory content is considered suspicious

Dependencies:
    * Python - Python 2.7.
        * On 64 bit windows, it is recommanded to use 64 bit version of Python.
    * pefile - Python PE parsing module
    * tqdm - Python progress meter module

Usage:
    Flags:
        The scripts support several flags to custom his operation:

        Name	                Short	Description
        --all	                -a	    Specify whether to show information about all of the modules instead of the
                                        suspicious ones only (optional)
        --group_by_processes	-g	    Specify whether to group the information by processes or not (optional)
        --output=<file>         -o	    Output file (Default: "DamPE-result.json")

    Example:
        DamPE.py --group_by_processes --output=DamPE-results.json

Source:
    DamPE - https://hexadite.com/DamPE/

License:
    GNU General Public License v3 - https://www.gnu.org/licenses/gpl-3.0.en.html

"""

__version__ = '1.0.0'
__author__ = 'or.virnik@hexadite.com'

import abc
import argparse
import ctypes
import json
import os
import platform
import pprint
import struct
import sys
import time
import traceback
import warnings

from ctypes.wintypes import DWORD, WORD, LPVOID, HMODULE, WCHAR, ULONG, HANDLE, BOOL, LPCVOID, get_last_error

LPDWORD = ctypes.POINTER(DWORD)
SIZE_T = ctypes.c_size_t
PSIZE_T = ctypes.POINTER(SIZE_T)

try:
    import pefile
    import tqdm
except ImportError:
    print >> sys.stderr, 'Please install the requirement.txt using "pip install -r requirement.txt"'
    exit(1)

PE_SIZE_LIMIT = 1024 * 1024 * 20  # 20 MB

# WinBase.h and WinDef.h definitions
MAX_MODULE_NAME32 = 255
MAX_PATH = 260
INVALID_HANDLE_VALUE = 0xFFFFFFFF
PSEUDO_PROCESSES = (0, 4)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx
PROCESS_VM_READ = 0x0010

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682489(v=vs.85).aspx
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684225(v=vs.85).aspx
class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', DWORD),
        ('th32ModuleID', DWORD),
        ('th32ProcessID', DWORD),
        ('GlblcntUsage', DWORD),
        ('ProccntUsage', DWORD),
        ('modBaseAddr', LPVOID),
        ('modBaseSize', DWORD),
        ('hModule', HMODULE),
        ('szModule', WCHAR * (MAX_MODULE_NAME32 + 1)),
        ('szExePath', WCHAR * MAX_PATH),
    ]

    @property
    def address(self):
        return self.modBaseAddr

    @property
    def size(self):
        return self.modBaseSize

    @property
    def path(self):
        return self.szExePath


LPMODULEENTRY32 = ctypes.POINTER(MODULEENTRY32)


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684839%28v=vs.85%29.aspx
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", LPDWORD),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", ULONG),
        ("dwFlags", DWORD),
        ("szExeFile", WCHAR * MAX_PATH),
    ]

    @property
    def pid(self):
        return self.th32ProcessID

    @property
    def ppid(self):
        return self.th32ParentProcessID

    @property
    def name(self):
        return self.szExeFile

    @property
    def is_pseudo(self):
        return self.pid in PSEUDO_PROCESSES


LPPROCESSENTRY32 = ctypes.POINTER(PROCESSENTRY32)


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("dwOemId", DWORD),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", LPDWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


LPSYSTEM_INFO = ctypes.POINTER(SYSTEM_INFO)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724381(v=vs.85).aspx
GetSystemInfo = ctypes.windll.kernel32.GetSystemInfo
GetSystemInfo.argtypes = [LPSYSTEM_INFO]
GetSystemInfo.restype = None

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682489%28v=vs.85%29.aspx
CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
CreateToolhelp32Snapshot.restype = HANDLE

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684218%28v=vs.85%29.aspx
Module32First = ctypes.windll.kernel32.Module32FirstW
Module32First.argtypes = [HANDLE, LPMODULEENTRY32]
Module32First.restype = BOOL

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684221%28v=vs.85%29.aspx
Module32Next = ctypes.windll.kernel32.Module32NextW
Module32Next.argtypes = [HANDLE, LPMODULEENTRY32]
Module32Next.restype = BOOL

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684834(v=vs.85).aspx
Process32First = ctypes.windll.kernel32.Process32FirstW
Process32First.argtypes = [HANDLE, LPPROCESSENTRY32]
Process32First.restype = BOOL

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684836%28v=vs.85%29.aspx
Process32Next = ctypes.windll.kernel32.Process32NextW
Process32Next.argtypes = [HANDLE, LPPROCESSENTRY32]
Process32Next.restype = BOOL

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211%28v=vs.85%29.aspx
CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = BOOL

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295%28v=vs.85%29.aspx
OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.argtypes = [DWORD, BOOL, DWORD]
OpenProcess.restype = HANDLE

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553%28v=vs.85%29.aspx
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, SIZE_T, PSIZE_T]
ReadProcessMemory.restype = BOOL


def assert_last_error(assert_expression=False, expected_errors={0}):
    """Assert the GLE value if assertion expression is false, and raise WindowsError if needed.

    Args:
        assert_expression (bool): Assert GLE only if that value is False.
        expected_errors (:obj:`set` of :obj:`int`): A Set of expected values for GLE.

    Raises:
        WindowsError: If `assert_expression` is False and the GLE is not in the `expected_errors`.

    """
    if not assert_expression:
        error_code = get_last_error()
        if error_code not in expected_errors:
            raise ctypes.WinError(error_code)


class SafeHandle(object):
    """A base class for guarding an handle in RAII manner."""

    def __init__(self):
        self._handle = None

    @abc.abstractmethod
    def _create_handle(self):
        """Creates an handle to guard.

        Returns:
            HANDLE: The created handle to guard.

        """
        raise NotImplemented

    def __enter__(self):
        """Creates the handle and validate him.

        Returns:
            SafeHandle: the current guard.

        Raises:
            AssertionError: if the handle is already opened.
        """
        assert self._handle is None, "SafeHandle can't be used in canonical 'with' statements"

        self._handle = self._create_handle()
        assert_last_error(self._handle != INVALID_HANDLE_VALUE)
        return self

    def _close(self):
        """Close the handle if needed.

        Raises:
            WindowsError: If the CloseHandle fails.

        """
        if self._handle is not None and self._handle != INVALID_HANDLE_VALUE:
            assert_last_error(CloseHandle(self._handle))
            self._handle = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the handle if needed.

        Raises:
            WindowsError: If the CloseHandle fails.

        """
        self._close()

    def __del__(self):
        """Close the handle if needed.

        Raises:
            WindowsError: If the CloseHandle fails.

        """
        self._close()


class Win32ListIterator(SafeHandle):
    """A base class for iterating win32api lists using first and next methods."""

    def _iter(self, items_type, first_func, next_func):
        """Iterate over a win32api list.

        Args:
            items_type (a subclass of :obj:ctypes.Structure): The type of the items to iterate.
            first_func (function): Function to get the first item of the list, signature: BOOL first_func(HANDLE, typ*).
            next_func (function): Function to get the next item of the list, signature: BOOL next_func(HANDLE, typ*).

        Returns:
            generator: The items of the list.

        Raises:
            WindowsError: If one of the functions fails.

        """

        # Create a struct to hold the current item
        current_item = items_type()

        # Initiate the struct with his size.
        current_item.dwSize = ctypes.sizeof(items_type)

        # Get the first item
        has_more_items = first_func(self._handle, ctypes.byref(current_item))

        # While we successfully got item from the list
        while has_more_items:
            yield current_item
            # Get the next item of the list.
            has_more_items = next_func(self._handle, ctypes.byref(current_item))

        # Assert that we didn't end up due to win32api error.
        assert_last_error()


class ProcessList(Win32ListIterator):
    """Process list generator."""

    def __iter__(self):
        """Iterate over the currently running process list.

        Returns:
            :obj:generator or :obj:PROCESSENTRY32: The currently running processes.

        Raises:
            WindowsError: If `Process32First` or `Process32Next` fails.
        """
        for process in self._iter(PROCESSENTRY32, Process32First, Process32Next):
            if not process.is_pseudo:
                yield process

    def _create_handle(self):
        """Creates a snapshot for process list.

        Returns:
            HANDLE: The created snapshot handle.

        """
        return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)


class ModuleList(Win32ListIterator):
    """Module list generator.

    Args:
        pid (int): The process id to iterate over his modules.

    """

    def __init__(self, pid):
        super(ModuleList, self).__init__()
        self._pid = pid

    def __iter__(self):
        """Iterate over the currently loaded modules of the given process.

        Returns:
            :obj:generator or :obj:MODULEENTRY32: The currently loaded modules of the given process.

        Raises:
            WindowsError: If `Module32First` or `Module32Next` fails.
        """
        return self._iter(MODULEENTRY32, Module32First, Module32Next)

    def _create_handle(self):
        """Creates a snapshot for module list.

        Returns:
            HANDLE: The created snapshot handle.

        """
        return CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self._pid)


def get_page_size():
    si = SYSTEM_INFO()
    GetSystemInfo(ctypes.byref(si))
    return si.dwPageSize


class RemoteProcessMemory(SafeHandle):
    """Wrapper for remote process memory reading.
    Enable access to process memory using `[]` operator.
    Managing cache for the most recently page.

    Args:
        pid (int): The process id to read memory from.
        address (int): The address to begin reading from within the given process.
        size (int): The size of the memory region to allow reading.
    """

    _PAGE_SIZE = get_page_size()

    def __init__(self, pid, address, size):
        super(RemoteProcessMemory, self).__init__()
        self._pid = pid
        self._address = address
        self._size = size
        self._last_page_data = None
        self._last_page_address = None

    def _create_handle(self):
        """Creates a process handle with permissions to read him memory.

        Returns:
            HANDLE: The created process handle.

        Raises:
            WindowsError: If `OpenProcess` fails.

        """
        process_handle = OpenProcess(PROCESS_VM_READ, 0, self._pid)
        assert_last_error(process_handle != 0)
        return process_handle

    def __len__(self):
        """Returns the size of the memory region.

        Returns:
            int: the size of the memory region.

        """
        return self._size

    def _read(self, address, size):
        """Reads from the remote process using cache.

        Args:
            address (int): The address to read from the remote process.
            size (int): The amount to read from the remote process.

        Returns:
            str: The requested memory.

        Raises:
            WindowsError: If the `ReadProcessMemory` fails.
            AssertionError: If the read returns wrong amount of data.

        """
        # If the result is in the cached page, return it from there.
        if self._last_page_address and \
                        self._last_page_address <= address and \
                                address + size <= self._last_page_address + self._PAGE_SIZE:
            return self._last_page_data[address - self._last_page_address:address - self._last_page_address + size]

        # Read each containing page.
        res = ''.join(self._read_page(i) for i in
                      range(address - address % self._PAGE_SIZE, address + size, self._PAGE_SIZE))

        return res[address % self._PAGE_SIZE:address % self._PAGE_SIZE + size]

    def _read_page(self, address):
        """Reads a page from the remote process.

        Args:
            address (int): The address to read from the remote process.

        Returns:
            str: The requested page of memory.

        Raises:
            WindowsError: If the `ReadProcessMemory` fails.
            AssertionError: If the read returns wrong amount of data.

        """
        # Allocate memory for the data
        buffer = ctypes.create_string_buffer(self._PAGE_SIZE)
        buf_size = SIZE_T(0)

        # Round down the address to align page
        address -= address % self._PAGE_SIZE

        # Read the actual memory
        result = ReadProcessMemory(self._handle,
                                   address,
                                   ctypes.byref(buffer),
                                   self._PAGE_SIZE,
                                   ctypes.byref(buf_size))

        # Assert validity of the reading
        assert_last_error(result != 0)
        assert buf_size.value == self._PAGE_SIZE

        # Update the cache
        self._last_page_data = buffer.raw
        self._last_page_address = address

        return buffer.raw

    def __getitem__(self, key):
        """Reads from the remote memory using `[]` operator.

        Args:
            key (:obj:slice or :obj:int): The indexes to slice and read by.

        Returns:
            str: The requested memory.

        Raises:
            WindowsError: If the `ReadProcessMemory` fails.
            AssertionError: If the read returns wrong amount of data or if the `key` has unsupported type.

        """
        if isinstance(key, slice):
            start, step, stop = key.start, key.step, key.stop
            if start is None:
                start = 0
            if stop is None:
                stop = len(self)
            return self._read(self._address + start, stop - start)[::step]
        elif isinstance(key, int):
            if key < 0:  # Handle negative indices
                key += len(self)
            if key < 0 or key >= len(self):
                raise IndexError, "The index (%d) is out of range." % key
            return self._read(self._address + key, 1)
        else:
            raise TypeError, "Invalid argument type."


class FileSizeAboveLimitError(Exception):
    """An exception for big files above the limit"""
    pass


class ModuleInfo(object):
    """Represent the information gathered about a module.

    Args:
        path (str): The base path of the module's executable.

    Attributes:
        path (str): The base path of the module's executable.
        instances (:obj:dict maps :obj:tuple of (:obj:int, :obj:int, :obj:int) to :obj:dict:): The instances of the
                                                                                               module in the processes.

    """

    def __init__(self, path):
        self.path = path
        self.instances = {}  # map from base address to hash

    def add_instance(self, pid, module):
        """Add instance to the module info.
        
        Args:
            pid (int): The process id where that instance observed. 
            module (MODULEENTRY32): The module instance. 

        Raises:
            WindowsError: If the `ReadProcessMemory` fails.
            AssertionError: If the read returns wrong amount of data.
            FileSizeAboveLimitError: If the module size is above the limit.

        """
        # If the module size is over our limit, ignore it.
        if module.size > PE_SIZE_LIMIT:
            raise FileSizeAboveLimitError()

        key = (pid, module.address, module.size)

        # If we already check that particular module, ignore it.
        if key in self.instances:
            return

        with RemoteProcessMemory(pid, module.address, module.size) as data_from_mem:
            pe_from_mem = pefile.PE(data=data_from_mem, fast_load=True)
            pe_from_disk = pefile.PE(self.path, fast_load=True)

            diff = list(get_pe_diff_by_fields(pe_from_mem, pe_from_disk))

            self.instances[key] = {'pid': pid,
                                   'address': module.address,
                                   'size': module.size,
                                   'is_suspicious': any(
                                       field in INTERESTING_HEADERS_FIELDS.get(header, []) for header, field in diff),
                                   'diff': diff,
                                   }

    def get_instances(self, get_all):
        """Get instance of the given module.

        Args:
            get_all (bool): Specify whether to return all or just the suspicious instances

        Returns:
            :obj:list of :obj:dict: The requested instance of the module.

        """
        if get_all:
            return self.instances.values()
        return filter(lambda instance: instance['is_suspicious'], self.instances.values())


def get_pe_diff_by_fields(pe1, pe2):
    """Compare all fields of PE headers of the given PEs and returns the difference.

    Args:
        pe1 (pefile.PE): The first PE to compare his headers.
        pe2 (pefile.PE): The second PE to compare his headers.

    Returns:
        (:obj:generator of :obj:tuple in form (:obj:str, :obj:str)): Generator of different fields in the headers
                                                                        of the PEs.

    """
    headers = ['DOS', 'FILE', 'OPTIONAL']
    for header in headers:
        h1 = getattr(pe1, '%s_HEADER' % header)
        h2 = getattr(pe2, '%s_HEADER' % header)
        for field in [field.split(',')[1] for field in getattr(pe1, '__IMAGE_%s_HEADER_format__' % header)[1]]:
            if getattr(h1, field, None) != getattr(h2, field, None):
                yield header, field


INTERESTING_HEADERS_FIELDS = {
    'DOS': {'e_lfanew'},
    'FILE': {'Characteristics', 'NumberOfSections'},
    'OPTIONAL': {'BaseOfData', 'MajorLinkerVersion', 'MinorLinkerVersion', 'MajorOperatingSystemVersion',
                 'MinorOperatingSystemVersion', 'SizeOfCode', 'SizeOfImage', 'SizeOfInitializedData',
                 'SizeOfStackCommit'}
}


def collect_modules(group_by_processes):
    """Collect information about modules currently loaded in the system.

    Args:
        group_by_processes: Specify whether to group the result by process or by modules.

    Returns:
        :obj:dict of :obj:ModuleInfo: The collected information organized as requested to.

    """
    res = {}
    pids = []
    # Prepare the process list information first.
    with ProcessList() as process_list:
        for process in process_list:
            if group_by_processes:
                res[process.pid] = {'pid': process.pid,
                                    'ppid': process.ppid,
                                    'name': process.name,
                                    'modules': {},
                                    }
            pids.append(process.pid)

    ignored_modules = set()

    # Collect the information about the loaded modules in the systems.
    for pid in tqdm.tqdm(pids):
        try:
            with ModuleList(pid) as module_list:
                for module in module_list:
                    try:
                        if group_by_processes:
                            modules = res[pid]['modules']
                        else:
                            modules = res

                        if module.path.lower() not in modules:
                            modules[module.path.lower()] = ModuleInfo(module.path)

                        modules[module.path.lower()].add_instance(pid, module)
                    except FileSizeAboveLimitError:
                        ignored_modules.add(module.path.lower())
                    except:
                        # Print the error and continue to execute
                        traceback.print_exc()
        except:
            # Print the error and continue to execute
            traceback.print_exc()

    if len(ignored_modules) > 0:
        print >> sys.stderr, 'Some modules were ignored due to the file size limit:'
        print >> sys.stderr, '\t' + '\n\t'.join(ignored_modules)

    return res


def is_64_machine():
    """Is the machine a 64 bit machine or 32 bit machine.

    Returns:
        bool: `True` if the machine is 64 bit machine, otherwise `False`.

    """
    return '64' in platform.machine()


def is_64_python():
    """Is the current python version a 64 bit version or 32 bit version.

    Returns:
        bool: `True` if the current python is a 64 bit version, otherwise `False`.

    """
    return struct.calcsize("P") == 8


def main():
    if is_64_machine() and not is_64_python():
        warnings.warn(
            'The script is executed from 32 bit version of python, therefore it is limited to check only 32 bit '
            'processes. Use 64 bit version of python in order to check both 32 and 64 bit processes')

    parser = argparse.ArgumentParser(description='Detect suspicious memory locations by comparing '
                                                 'the PE file on disk to the memory content')
    parser.add_argument('-a', '--all', action='store_true', dest='show_all',
                        help='Specify whether to show information about all of the modules instead '
                             'of the suspicious ones only')
    parser.add_argument('-g', '--group_by_processes', action='store_true', dest='group_by_processes',
                        help='Specify whether to group the information by processes or not')
    parser.add_argument('-o', '--output', dest='output', help='Output file', default='DamPE-result.json')

    args = parser.parse_args()

    s = time.time()
    res = {}
    modules = collect_modules(args.group_by_processes)
    if args.group_by_processes:
        for pid, process_info in modules.iteritems():
            modules_to_show = {}
            for name, module_info in process_info['modules'].iteritems():
                instances_to_show = module_info.get_instances(args.show_all)
                if args.show_all or len(instances_to_show) > 0:
                    modules_to_show[name] = instances_to_show

            if args.show_all or len(modules_to_show) > 0:
                res[pid] = {'name': process_info['name'],
                            'pid': process_info['pid'],
                            'ppid': process_info['ppid'],
                            'modules': modules_to_show
                            }
    else:
        for name, module_info in modules.iteritems():
            instances_to_show = module_info.get_instances(args.show_all)
            if len(instances_to_show) > 0:
                res[name] = instances_to_show

    print >> sys.stderr, ''
    print >> sys.stderr, 'Saving results to', os.path.abspath(args.output)

    # Save the result to the requested file
    with open(args.output, 'wb') as output:
        json.dump(res, output)

    print >> sys.stderr, 'took %.02f seconds' % (time.time() - s)

    if len(res) == 0:
        print 'No results found'
    elif len(res) < 10:
        pprint.pprint(res)
    else:
        print 'Results can be found at', os.path.abspath(args.output)


if __name__ == '__main__':
    os.system('color a')
    main()
