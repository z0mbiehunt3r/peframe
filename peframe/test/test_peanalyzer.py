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

import os
import unittest

from peframe.analyzer import PEAnalyzer


TESTS_BASEPATH = os.path.dirname(os.path.abspath(__file__))


class PEAnalyzerTestCase(unittest.TestCase):
    """"""

    @classmethod
    def setUpClass(cls):
        cls.analyzer = PEAnalyzer()

    def test_antivm_tricks_detection(self):
        """"""
        expected_antivm_tricks = ['VirtualPc trick']
        antivm_sample_path = \
            os.path.join(TESTS_BASEPATH, 'samples',
                         '0c95e89094915011a1e477c31341b771.exe')
        self.analyzer.file_path = antivm_sample_path
        detected_antivm_tricks = self.analyzer.detect_antivm_tricks()

        self.assertItemsEqual(detected_antivm_tricks,
                              expected_antivm_tricks)
        self.assertItemsEqual(self.analyzer.detected_antivm,
                              expected_antivm_tricks)

    def test_suspicious_api_detection(self):
        """"""
        expected_suspicious_api = \
            ['GetCurrentProcess', 'TerminateProcess', 'WriteFile',
             'UnhandledExceptionFilter', 'IsDebuggerPresent', 'ExitProcess',
             'Sleep', 'GetTickCount', 'GetProcAddress']
        suspicious_api_sample_path = \
            os.path.join(TESTS_BASEPATH, 'samples',
                         '0c95e89094915011a1e477c31341b771.exe')
        self.analyzer.file_path = suspicious_api_sample_path
        detected_suspicious_api = self.analyzer.detect_suspicious_apis()

        self.assertItemsEqual(detected_suspicious_api,
                              expected_suspicious_api)
        self.assertItemsEqual(detected_suspicious_api,
                              self.analyzer.detected_suspiciousapi)

    def test_antidebugger_detection(self):
        """"""
        expected_antidebugger = \
            ['GetLastError', 'IsDebuggerPresent', 'TerminateProcess',
             'UnhandledExceptionFilter']
        antidebugger_sample_path = \
            os.path.join(TESTS_BASEPATH, 'samples',
                         '0c95e89094915011a1e477c31341b771.exe')
        self.analyzer.file_path = antidebugger_sample_path
        detected_antidebugger = self.analyzer.detect_antidebugger()

        self.assertItemsEqual(detected_antidebugger,
                              expected_antidebugger)
        self.assertItemsEqual(self.analyzer.detected_antidebugger,
                              expected_antidebugger)

    def test_md5hash(self):
        """"""
        expected_md5_hash = '0c95e89094915011a1e477c31341b771'
        sample_path = os.path.join(TESTS_BASEPATH, 'samples',
                                   '0c95e89094915011a1e477c31341b771.exe')
        self.analyzer.file_path = sample_path
        computed_md5_hash = self.analyzer.compute_md5hash()

        self.assertEqual(computed_md5_hash, expected_md5_hash)
        self.assertEqual(self.analyzer.md5_hash, expected_md5_hash)

    def test_sha1hash(self):
        """"""
        expected_sha1_hash = 'e9b27b8710ed9d4a7eed4b824bc6d1ec74ae4d22'
        sample_path = os.path.join(TESTS_BASEPATH, 'samples',
                                   '0c95e89094915011a1e477c31341b771.exe')
        self.analyzer.file_path = sample_path
        computed_sha1_hash = self.analyzer.compute_sha1hash()

        self.assertEqual(computed_sha1_hash, expected_sha1_hash)
        self.assertEqual(self.analyzer.sha1_hash, expected_sha1_hash)

    def test_imphash(self):
        """"""
        expected_imphash = '9e20a7cfc9bb65f0c47d388b2cefb1ff'
        sample_path = os.path.join(TESTS_BASEPATH, 'samples',
                                   '0c95e89094915011a1e477c31341b771.exe')
        self.analyzer.file_path = sample_path
        computed_imphash = self.analyzer.compute_imphash()

        self.assertEqual(computed_imphash, expected_imphash)
        self.assertEqual(self.analyzer.imphash, expected_imphash)

    def test_packers_detection(self):
        """"""
        expected_packers = ['Microsoft Visual C++ 8',
                            'VC8 -> Microsoft Corporation']
        packed_sample_path = \
            os.path.join(TESTS_BASEPATH, 'samples',
                         '0c95e89094915011a1e477c31341b771.exe')
        self.analyzer.file_path = packed_sample_path
        detected_packers = self.analyzer.detect_packers()

        self.assertItemsEqual(detected_packers,
                              expected_packers)
        self.assertItemsEqual(self.analyzer.detected_packers,
                              expected_packers)

    def test_xor_detection(self):
        """"""
        xor_sample_path = \
            os.path.join(TESTS_BASEPATH, 'samples',
                         '0c95e89094915011a1e477c31341b771.exe')
        self.analyzer.file_path = xor_sample_path

        self.assertRaises(NotImplementedError,
                          lambda: self.analyzer.detect_xor())

    def test_uri_extraction(self):
        """"""
        self.assertRaises(NotImplementedError,
                          lambda: self.analyzer.extract_fileurl())

    def test_suspicious_sections_detection(self):
        """"""
        expected_suspicious_sections = [
            {'section': '.text',
             'sha1_hash': 'fe6928627056ca93938be81b9add4e73c135c1fc',
             'md5_hash': '18b2f93005c2ac0671dc18d192bcc920'}
        ]
        suspicious_sections_sample_path = \
            os.path.join(TESTS_BASEPATH, 'samples',
                         '0a854e790ff63c0e56f08b5e65088b90.exe')
        self.analyzer.file_path = suspicious_sections_sample_path
        detected_suspicious_sections = self.analyzer.detect_suspicious_sections()

        self.assertItemsEqual(detected_suspicious_sections,
                              expected_suspicious_sections)
        self.assertItemsEqual(self.analyzer.section_alerts,
                              expected_suspicious_sections)

    def test_certificate_extraction(self):
        """"""
        expected_certificate = {
            'block_size': 3752,
            'virtual_address': 978480,
            'sha1_hash': '5fd137414268c12055cfdd1d292af5d4a76c57d7',
            'signed': True,
            'md5_hash': '0b76fb8fa68817b4cf733b3a218af1fb'
        }
        signed_sample_path = os.path.join(
            TESTS_BASEPATH, 'samples', '0a854e790ff63c0e56f08b5e65088b90.exe')
        self.analyzer.file_path = signed_sample_path
        extracted_certificate = self.analyzer.extract_digital_signature()

        self.assertDictEqual(extracted_certificate, expected_certificate)
        self.assertDictEqual(self.analyzer.cert_dict, expected_certificate)

    def test_metadata_extraction(self):
        """"""
        expected_metadata = {
            'LegalCopyright': 'Copyright (C) 2014',
            'InternalName': 'SetupWizard.exe',
            'FileVersion': '3.4.5.2',
            'FileDescription': 'Setup Wizard',
            'Translation': '0x0c0a 0x04b0',
            'ProductName': 'SetupWizard',
            'OriginalFilename': 'SetupWizard.exe',
            'ProductVersion': '3.4.5.2'
        }
        sample_path = os.path.join(
            TESTS_BASEPATH, 'samples', '0a854e790ff63c0e56f08b5e65088b90.exe')
        self.analyzer.file_path = sample_path
        extracted_metadata = self.analyzer.extract_metadata()

        self.assertDictEqual(extracted_metadata, expected_metadata)
        self.assertDictEqual(self.analyzer.metadata, expected_metadata)

    def test_metadata_extraction_no_fileinfoattr(self):
        """"""
        sample_path = os.path.join(
            TESTS_BASEPATH, 'samples', '0a854e790ff63c0e56f08b5e65088b90.exe')
        self.analyzer.file_path = sample_path
        self.analyzer._load_pe()
        delattr(self.analyzer._pe, 'FileInfo')
        extracted_metadata = self.analyzer.extract_metadata()

        self.assertDictEqual(extracted_metadata, {})
        self.assertDictEqual(self.analyzer.metadata, {})

    def test_directories_addresses_extraction(self):
        """"""
        expected_addresses = {
            'tls': 0,
            'resource': 20480,
            'relocation': 32768,
            'export': 0,
            'debug': 12464,
            'import': 13024,
            'security': 315392
        }
        sample_path = os.path.join(
            TESTS_BASEPATH, 'samples', '0a9c6896362aac1b543ebf96fdda8640.exe')
        self.analyzer.file_path = sample_path
        extracted_addresses = self.analyzer.extract_directories_addresses()

        self.assertDictEqual(extracted_addresses, expected_addresses)
        self.assertDictEqual(self.analyzer.directories_addresses,
                             expected_addresses)