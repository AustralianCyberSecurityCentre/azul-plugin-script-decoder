"""
Script Decoder Test Suite
=========================
Test plugin to decode files encoded using Microsoft's
script obfuscation tool.

"""

from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    Filepath,
    JobResult,
    State,
    Uri,
    test_template,
)

from azul_plugin_script_decoder.main import AzulPluginScriptDecoder


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginScriptDecoder

    def test_malicious_jscript(self):
        """A JScript.Encoded sample"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "652566914671a9d5fb5ad0b75b6c9023fa8c9cff2c2d2254daad78ba40c14e0b",
                        "Malicious JavaScript file, malware family nemucod.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="652566914671a9d5fb5ad0b75b6c9023fa8c9cff2c2d2254daad78ba40c14e0b",
                        data=[
                            EventData(
                                hash="bbc6275f157e997b85916664916bc87e816a7cebb729f56e02a0b2b5e5fb1615", label="text"
                            )
                        ],
                        features={"tag": [FV("encoded_script", offset=0, size=516971)]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="652566914671a9d5fb5ad0b75b6c9023fa8c9cff2c2d2254daad78ba40c14e0b",
                        ),
                        entity_type="binary",
                        entity_id="bbc6275f157e997b85916664916bc87e816a7cebb729f56e02a0b2b5e5fb1615",
                        relationship={"action": "decoded"},
                        data=[
                            EventData(
                                hash="bbc6275f157e997b85916664916bc87e816a7cebb729f56e02a0b2b5e5fb1615",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("decoded_script")]},
                    ),
                ],
                data={"bbc6275f157e997b85916664916bc87e816a7cebb729f56e02a0b2b5e5fb1615": b""},
            ),
        )

    def test_malicious_jscript_embedded(self):
        """A JScript.Encoded sample embedded in a dummied HTML script block"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "dbe947a1d1935df56a5989dd88aa9e5e458e5024848f4b8e990375fa8518ff75",
                        "Malicious JavaScript file, embedded in a dummy HTML file with a script block, malware family nemucod.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="dbe947a1d1935df56a5989dd88aa9e5e458e5024848f4b8e990375fa8518ff75",
                        data=[
                            EventData(
                                hash="bbc6275f157e997b85916664916bc87e816a7cebb729f56e02a0b2b5e5fb1615",
                                label="text",
                                language="javascript",
                            )
                        ],
                        features={"tag": [FV("encoded_script", offset=48, size=516971)]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="dbe947a1d1935df56a5989dd88aa9e5e458e5024848f4b8e990375fa8518ff75",
                        ),
                        entity_type="binary",
                        entity_id="bbc6275f157e997b85916664916bc87e816a7cebb729f56e02a0b2b5e5fb1615",
                        relationship={"action": "decoded", "offset": "0x30", "language": "jscript"},
                        data=[
                            EventData(
                                hash="bbc6275f157e997b85916664916bc87e816a7cebb729f56e02a0b2b5e5fb1615",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("decoded_script")]},
                    ),
                ],
                data={"bbc6275f157e997b85916664916bc87e816a7cebb729f56e02a0b2b5e5fb1615": b""},
            ),
        )

    def test_invalid_filetype(self):
        """Tests on wrong file format"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "2263c7a1b9db691b9619cf0565eb1f06c2b37aa0ddbbca7bd359c774145c37ed", "Dummy compiled java file."
                    ),
                )
            ]
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))
