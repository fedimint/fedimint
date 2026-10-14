"""Remove incidental Nix references from container ELF debug information only.

Nix scans raw store hashes, including literals inside compressed DWARF. Editing
those compressed bytes directly can corrupt the stream, and removing references
from the whole executable can destroy real runtime paths. Decompress first,
edit only non-allocated debug sections without changing DWARF offsets, then
recompress. The original non-container package retains its original source paths.
"""

import hashlib
import io
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zlib

from elftools.elf.elffile import ELFFile
import zstandard


# DWARF can split "/nix/store" into a directory entry and "HASH-package/file"
# into a file entry. Recognize the store-name component, not only full paths.
STORE_HASH = re.compile(rb"(?<![0-9a-z])([0-9abcdfghijklmnpqrsvwxyz]{32})(?=-)")


def sanitize_section(elf, section, payload):
    """Retain section format and DWARF offsets, including compression headers."""
    if section["sh_flags"] & 0x2:  # SHF_ALLOC
        raise ValueError(f"allocated debug section: {section.name}")
    if section["sh_type"] != "SHT_PROGBITS":
        raise ValueError(f"unexpected debug section: {section.name}")
    header = b""
    compression = None
    expected_size = len(payload)
    if section["sh_flags"] & 0x800:  # SHF_COMPRESSED
        size = elf.structs.Elf_Chdr.sizeof()
        header, payload = payload[:size], payload[size:]
        fields = elf.structs.Elf_Chdr.parse(header)
        compression = fields["ch_type"]
        if compression == "ELFCOMPRESS_ZLIB":
            compression = 1
        expected_size = fields["ch_size"]
    if compression == 1:
        data = zlib.decompress(payload)
    elif compression == 2:
        # Wild can concatenate several zstd frames within one ELF section.
        with zstandard.ZstdDecompressor().stream_reader(
            io.BytesIO(payload), read_across_frames=True
        ) as reader:
            data = reader.read(expected_size + 1)
    elif compression is None:
        data = payload
    else:
        raise ValueError(f"unsupported debug compression: {compression}")
    if len(data) != expected_size:
        raise ValueError(f"incorrect debug section size: {section.name}")
    replacement = STORE_HASH.sub(b"e" * 32, data)
    if compression == 1:
        replacement = zlib.compress(replacement)
    elif compression == 2:
        replacement = zstandard.ZstdCompressor(write_checksum=True).compress(replacement)
    return header + replacement


def compression_flags(path, names, enabled):
    """Make compressed payloads opaque to objcopy while replacing them."""
    with path.open("r+b") as stream:
        elf = ELFFile(stream)
        table_start = elf["e_shoff"]
        table_end = table_start + elf.num_sections() * elf["e_shentsize"]
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD" and (
                table_start < segment["p_offset"] + segment["p_filesz"]
                and segment["p_offset"] < table_end
            ):
                raise ValueError("cannot change a loadable section table")
        for index, section in enumerate(list(elf.iter_sections())):
            if section.name not in names:
                continue
            flags = section["sh_flags"]
            if enabled:
                flags |= 0x800
            else:
                flags &= ~0x800
            # sh_flags starts at byte 8 in both ELF32 and ELF64 section headers.
            stream.seek(elf["e_shoff"] + index * elf["e_shentsize"] + 8)
            encoding = ("<" if elf.little_endian else ">") + (
                "Q" if elf.elfclass == 64 else "I"
            )
            stream.write(struct.pack(encoding, flags))


def runtime_image(path):
    """Fingerprint loadable bytes, allowing only ELF section-table metadata changes."""
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        # objcopy relocates the non-loadable section table. Its location
        # is in the ELF header, which is itself usually covered by PT_LOAD.
        section_metadata = [(40, 48)] if elf.elfclass == 64 else [(32, 36)]
        result = []
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            data = bytearray(segment.data())
            start = segment["p_offset"]
            for first, last in section_metadata:
                if start <= first and last <= start + len(data):
                    data[first - start:last - start] = bytes(last - first)
            result.append((dict(segment.header), hashlib.sha256(data).digest()))
        return result


def sanitize(path):
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            return
    original_runtime = runtime_image(path)
    original_mode = stat.S_IMODE(path.stat().st_mode)
    with tempfile.TemporaryDirectory() as directory:
        temporary = pathlib.Path(directory) / "binary"
        opaque_input = pathlib.Path(directory) / "input"
        # Wild puts the original section table inside PT_LOAD. A plain objcopy
        # moves the table out before we temporarily change compression flags.
        subprocess.run(["llvm-objcopy", str(path), str(opaque_input)], check=True)
        opaque_input.chmod(0o600)
        command = ["llvm-objcopy"]
        compressed = set()
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            for index, section in enumerate(elf.iter_sections()):
                if not section.name.startswith((".debug_", ".zdebug_")):
                    continue
                # Rust's .debug_gdb_scripts is allocated. A name alone does
                # not make a section safe to rewrite; retain all runtime data.
                if section["sh_flags"] & 0x2:
                    continue
                if section.name.startswith(".zdebug_"):
                    raise ValueError("legacy GNU debug compression is unsupported")
                if section["sh_flags"] & 0x800:
                    compressed.add(section.name)
                stream.seek(section["sh_offset"])
                replacement = sanitize_section(
                    elf, section, stream.read(section["sh_size"])
                )
                section_file = pathlib.Path(directory) / str(index)
                section_file.write_bytes(replacement)
                command.extend(["--update-section", f"{section.name}={section_file}"])
        # Let objcopy lay out the replacement sections, but do not ask it to
        # decode them: the pinned LLVM/binutils builds lack the zstd codec.
        compression_flags(opaque_input, compressed, enabled=False)
        subprocess.run(command + [str(opaque_input), str(temporary)], check=True)
        compression_flags(temporary, compressed, enabled=True)
        if runtime_image(temporary) != original_runtime:
            raise ValueError(f"objcopy changed loadable content: {path}")
        # The copied Nix output is read-only. Restore its mode even on failure.
        path.chmod(original_mode | stat.S_IWUSR)
        try:
            shutil.copyfile(temporary, path)
        finally:
            path.chmod(original_mode)


if __name__ == "__main__":
    for argument in sys.argv[1:]:
        sanitize(pathlib.Path(argument))
