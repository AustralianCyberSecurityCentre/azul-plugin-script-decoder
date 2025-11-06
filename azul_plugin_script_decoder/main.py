"""ScrEnc.exe encoded script decoder.

This plugin decodes Scripts and HTML encoded by Microsoft's screnc.exe tool.
That tool performs obfuscation of script sources (VBScript/JScript) using
a substituion cipher into their encoded versions (eg. vbscript.encode).

Didier Steven's decode-vbe utility is used under-the-hood to deobfuscate.
"""

import re

from azul_runner import (
    BinaryPlugin,
    Feature,
    FeatureValue,
    Job,
    add_settings,
    cmdline_run,
)

from .didier.decode_vbe import Decode


class AzulPluginScriptDecoder(BinaryPlugin):
    """Encoded script decoder plugin."""

    VERSION = "2025.03.19"
    SETTINGS = add_settings(
        # run on all types as may be embedded in other files
        filter_data_types={"content": []},
    )
    FEATURES = [
        Feature(name="tag", desc="Any informational label about the sample", type=str),
    ]

    PATTERN = rb"#@~\^......==(.+)......==\^#~@"
    SCRIPT_TYPES = [
        b"jscript",
        b"vbscript",
    ]

    def execute(self, job: Job):
        """Regex for screnc marker and decode using decode-vbe script."""
        data = job.get_data()
        buf = data.read()
        # We do our own regexing as underlying tool expects only single instance
        # of encoded script which may not be the case when embedded in pages and
        # we want to record the offsets.
        for m in re.finditer(AzulPluginScriptDecoder.PATTERN, buf):
            offset = m.start()
            size = m.end() - offset
            self.add_feature_values("tag", FeatureValue("encoded_script", offset=offset, size=size))
            child_features = {}
            rel_features = {
                "action": "decoded",
            }
            if offset:
                rel_features["offset"] = "0x%02x" % offset

            # see if we can grab the type from script tag
            # will only work if embedded in html/asp/etc.
            for t in AzulPluginScriptDecoder.SCRIPT_TYPES:
                # eg. <% @language="VBScript.Encode" %>
                if t in buf[max(0, offset - 30) : offset].lower():
                    rel_features["language"] = t.decode("utf-8")
                    child_features["tag"] = "decoded_%s" % t.decode("utf-8")
                else:
                    child_features["tag"] = "decoded_script"

            deob = Decode(m.group(1))
            # any other validity checks?
            # a failed decode will just be garbage output
            if deob:
                c = self.add_child_with_data(rel_features, deob)
                c.add_many_feature_values(child_features)
                # Save the decoded script as a text stream for display
                # use prismjs language tags for syntax highlighting
                stream_tags = {}
                if rel_features.get("language") == "vbscript" or all(w in deob for w in [b"Dim ", b"Sub ", b"End"]):
                    stream_tags["language"] = "visual-basic"
                elif rel_features.get("language") == "jscript" or all(w in deob for w in [b"document.write", b";"]):
                    stream_tags["language"] = "javascript"
                self.add_data("text", stream_tags, deob)


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginScriptDecoder)


if __name__ == "__main__":
    main()
