# ----------------------------------------------------------------------
# This file is part of PEframe.
#
# PEframe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# PEframe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PEframe. If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------

# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import os
import re
import string

try:
    import rfc3987
except ImportError:
    print 'You need rfc3987 module, check https://pypi.python.org/pypi/rfc3987'

from peframe.thirdparty import pefile, peutils


class PEAnalyzer(object):
    """"""

    __slots__ = ['_file_path', '_pe', '_pe_raw', '_sig_db', 'detected_antivm',
                 '_antidebugger_signatures', '_suspiciousapi_signatures',
                 'xor_detected', 'imported_libs', 'detected_suspiciousapi',
                 'section_alerts', 'detected_packers', 'metadata',
                 'directories_addresses', 'cert_dict', 'vm_tricks',
                 'imphash', 'md5_hash', 'sha1_hash', 'file_name', 'file_size',
                 'antidebugger_signatures', 'detected_antidebugger',
                 'is_dll', 'num_sections', 'timestamp', 'timestamp_date',
                 'extracted_strings', '_uri_matcher', 'extracted_uris']

    @property
    def file_path(self):
        """
        """
        return self._file_path

    @file_path.setter
    def file_path(self, file_path):
        """Useful to assure cleanup from previous analysis when analyzing
        a new PE file
        """
        self._file_path = file_path
        self._pe = None
        self._pe_raw = None
        self.cert_dict = {}
        self.detected_antidebugger = set()
        self.detected_antivm = []
        self.detected_packers = set()
        self.detected_suspiciousapi = set()
        self.directories_addresses = {}
        self.extracted_strings = tuple()
        self.extracted_uris = tuple()
        self.file_name = None
        self.file_size = None
        self.imphash = None
        self.imported_libs = set()
        self.is_dll = None
        self.md5_hash = None
        self.metadata = {}
        self.num_sections = None
        self.section_alerts = []
        self.sha1_hash = None
        self.timestamp = None
        self.timestamp_date = None
        self.xor_detected = []

    def __init__(self, file_path=None):
        """Constructor for PEAnalyzer"""
        self.file_path = file_path
        self._antidebugger_signatures = None
        self._suspiciousapi_signatures = None
        self._sig_db = None

        # Credits: Joxean Koret
        self.vm_tricks = {
            'Red Pill': '\x0f\x01\x0d\x00\x00\x00\x00\xc3',
            'VirtualPc trick': '\x0f\x3f\x07\x0b',
            'VMware trick': 'VMXh',
            'VMCheck.dll': '\x45\xC7\x00\x01',
            'VMCheck.dll for VirtualPC':
                '\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff',
            'Xen': 'XenVMM',  # Or XenVMMXenVMM
            'Bochs & QEmu CPUID Trick': '\x44\x4d\x41\x63',
            'Torpig VMM Trick': '\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3',
            'Torpig (UPX) VMM Trick': '\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3'
        }

        self._uri_matcher = rfc3987.get_compiled_pattern('^%(URI)s$')

        analyzer_basepath = os.path.dirname(os.path.abspath(__file__))
        signatures_path = os.path.join(analyzer_basepath, 'signatures')

        alerts_path = os.path.join(signatures_path, 'alerts.txt')
        antidbg_path = os.path.join(signatures_path, 'antidbg.txt')
        userdb_path = os.path.join(signatures_path, 'userdb.txt')
        with open(userdb_path, 'r') as fd:
            fn_userdb = fd.read()
        self._sig_db = peutils.SignatureDatabase(data=fn_userdb)
        with open(antidbg_path, 'r') as fd:
            antidbgs = fd.readlines()
        self._antidebugger_signatures = set([antidbg.strip()
                                             for antidbg in antidbgs])
        with open(alerts_path, 'r') as fd:
            alerts = fd.readlines()
        self._suspiciousapi_signatures = set([apialert.strip()
                                              for apialert in alerts])

    def _load_pe(self):
        """"""
        with open(self._file_path, 'rb') as fd:
            self._pe_raw = fd.read()
        self._pe = pefile.PE(data=self._pe_raw)

        dei = hasattr(self._pe, 'DIRECTORY_ENTRY_IMPORT')
        if dei:
            self.imported_libs = \
                set([imp.name for lib in self._pe.DIRECTORY_ENTRY_IMPORT
                     for imp in lib.imports])

        self.file_name = os.path.basename(self._file_path)
        self.file_size = os.path.getsize(self._file_path)

        self.is_dll = self._pe.FILE_HEADER.IMAGE_FILE_DLL
        self.num_sections = self._pe.FILE_HEADER.NumberOfSections
        self.timestamp = self._pe.FILE_HEADER.TimeDateStamp
        self.timestamp_date = datetime.datetime.fromtimestamp(self.timestamp)

    @property
    def pe_loaded(self):
        """"""
        return self._pe is not None

    def extract_directories_addresses(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()

        # The directory of imported symbols
        dir_import = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ].VirtualAddress
        # The directory of exported symbols; mostly used for DLLs.
        dir_export = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
        ].VirtualAddress
        # Debug directory - contents is compiler dependent.
        dir_debug = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']
        ].VirtualAddress
        # Thread local storage directory - structure unknown;
        # contains variables that are declared
        dir_tls = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']
        ].VirtualAddress
        # The resources, such as dialog boxes, menus, icons and so on,
        # are stored in the data directory
        dir_resource = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
        ].VirtualAddress
        # PointerToRelocations, NumberOfRelocations, NumberOfLinenumbers
        dir_relocation = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']
        ].VirtualAddress
        # PointerToRelocations, NumberOfRelocations, NumberOfLinenumbers
        dir_security = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ].VirtualAddress

        self.directories_addresses = {
            'import': dir_import,
            'export': dir_export,
            'debug': dir_debug,
            'tls': dir_tls,
            'resource': dir_resource,
            'relocation': dir_relocation,
            'security': dir_security
        }
        return self.directories_addresses

    def compute_imphash(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        # Import Hash
        # https://www.mandiant.com/blog/tracking-malware-import-hashing/
        self.imphash = self._pe.get_imphash()
        return self.imphash

    def compute_md5hash(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        self.md5_hash = hashlib.md5(self._pe_raw).hexdigest()
        return self.md5_hash

    def compute_sha1hash(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        self.sha1_hash = hashlib.sha1(self._pe_raw).hexdigest()
        return self.sha1_hash

    def extract_digital_signature(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        cert_md5 = False
        cert_sha1 = False
        signed = False

        cert_address = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ].VirtualAddress
        cert_size = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        if cert_address != 0 and cert_size != 0:
            signature = self._pe.write()[cert_address + 8:]
            cert_md5 = hashlib.md5(signature).hexdigest()
            cert_sha1 = hashlib.sha1(signature).hexdigest()
            signed = True

        self.cert_dict = {
            'virtual_address': cert_address,
            'block_size': cert_size,
            'md5_hash': cert_md5,
            'sha1_hash': cert_sha1,
            'signed': signed
        }
        return self.cert_dict

    def detect_packers(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        matches = self._sig_db.match_all(self._pe, ep_only=True)
        # >>> matches[0]
        # ['UPX v0.80 - v0.84']
        if matches is not None:
            self.detected_packers = set([match[0] for match in matches])
        return self.detected_packers

    def detect_antidebugger(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        self.detected_antidebugger = self.imported_libs.intersection(
            self._antidebugger_signatures)
        return self.detected_antidebugger

    def detect_antivm_tricks(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        for product, trick in self.vm_tricks.iteritems():
            if self._pe_raw.find(trick) > -1:
                self.detected_antivm.append(product)
        return self.detected_antivm

    def detect_xor(self):
        """
        http://www.cloudshield.com/blog/advanced-malware/how-to-efficiently-detect-xor-encoded-content-part-1-of-2/
        """
        # if not self.pe_loaded:
        # self._load_pe()
        raise NotImplementedError()

    def detect_suspicious_apis(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        self.detected_suspiciousapi = \
            self.imported_libs.intersection(self._suspiciousapi_signatures)
        return self.detected_suspiciousapi

    def detect_suspicious_sections(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()

        for section in self._pe.sections:
            if section.SizeOfRawData == 0 or 0 < section.get_entropy() < 1 \
                    or section.get_entropy() > 7:
                section_name = ''.join([char for char in section.Name
                                        if char in string.printable])
                md5 = section.get_hash_md5()
                sha1 = section.get_hash_sha1()
                alert = {
                    'section': section_name,
                    'md5_hash': md5,
                    'sha1_hash': sha1
                }
                self.section_alerts.append(alert)
        return self.section_alerts

    def extract_strings(self, min_length=6):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        # already extracted, just return them
        if len(self.extracted_strings) > 0:
            return self.extracted_strings

        # regex from cuckoo project
        strings = tuple(found.strip() for found in
                        re.findall('[\x1f-\x7e]{%s,}' %
                                   min_length, self._pe_raw))
        strings += tuple(str(ws.decode("utf-16le")).strip()
                         for ws in re.findall('(?:[\x1f-\x7e][\x00]){%s,}'
                                              % min_length, self._pe_raw))
        self.extracted_strings = strings
        return self.extracted_strings

    def extract_uris(self, min_length=10):
        """"""
        if not self.pe_loaded:
            self._load_pe()
        # used when calling .extract_fileurl() before .extract_strings()
        if len(self.extracted_strings) <= 0:
            self.extract_strings()

        self.extracted_uris = tuple(uri for uri in self.extracted_strings if
                                    len(uri) > min_length and
                                    self._uri_matcher.match(uri))
        return self.extracted_uris

    def extract_metadata(self):
        """"""
        if not self.pe_loaded:
            self._load_pe()

        if not hasattr(self._pe, 'FileInfo'):
            return {}

        for entry in self._pe.FileInfo:
            if hasattr(entry, 'StringTable'):
                for st_entry in entry.StringTable:
                    for str_entry in st_entry.entries.items():
                        self.metadata.update({str_entry[0]: str_entry[1]})
            elif hasattr(entry, 'Var'):
                for var_entry in entry.Var:
                    if hasattr(var_entry, 'entry'):
                        k = var_entry.entry.keys()[0]
                        v = var_entry.entry[k]
                        self.metadata.update({k: v})
        return self.metadata

    @property
    def json(self):
        """"""
        info_dict = {
            'antidebugger': list(self.detected_antidebugger),
            'antivm_tricks': list(self.detected_antivm),
            'cert_info': self.cert_dict,
            'compile_time': self.timestamp_date.__str__(),
            'directories': self.directories_addresses,
            'is_dll': self.is_dll,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'imphash': self.imphash,
            'md5_hash': self.md5_hash,
            'metadata': self.metadata,
            'num_sections': self.num_sections,
            'packers': list(self.detected_packers),
            'section_alerts': list(self.section_alerts),
            'strings': tuple(self.extracted_strings),
            'uris': tuple(self.extracted_uris),
            'sha1_hash': self.sha1_hash,
            'suspicious_apis': list(self.detected_suspiciousapi),
            'xor_detected': list(self.xor_detected),
        }
        return json.dumps(info_dict, indent=4, separators=(',', ': '))

    @property
    def dict(self):
        return json.loads(self.json)

    @classmethod
    def generate_json_report(cls, file_path):
        """"""
        analyzer = PEAnalyzer(file_path)
        analyzer.compute_md5hash()
        analyzer.compute_sha1hash()
        analyzer.compute_imphash()
        analyzer.detect_packers()
        analyzer.extract_digital_signature()
        analyzer.detect_antidebugger()
        analyzer.detect_antivm_tricks()
        # analyzer.detect_xor()
        analyzer.detect_suspicious_apis()
        analyzer.detect_suspicious_sections()
        analyzer.extract_metadata()
        analyzer.extract_uris()
        analyzer.extract_strings()
        analyzer.extract_directories_addresses()
        return analyzer.json

    def analyze(self, file_path):
        self.file_path = file_path
        self.compute_md5hash()
        self.compute_sha1hash()
        self.compute_imphash()
        self.detect_packers()
        self.extract_digital_signature()
        self.detect_antidebugger()
        self.detect_antivm_tricks()
        # self.detect_xor()
        self.detect_suspicious_apis()
        self.detect_suspicious_sections()
        self.extract_metadata()
        self.extract_uris()
        self.extract_strings()
        self.extract_directories_addresses()