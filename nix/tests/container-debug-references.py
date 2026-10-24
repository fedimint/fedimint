"""Small native ELF fixtures; never runs downloaded release binaries."""

import hashlib
import io
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

from elftools.elf.elffile import ELFFile
import zstandard


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def sections(path):
    result = {}
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if not section.name.startswith(".debug_"):
                continue
            stream.seek(section["sh_offset"])
            payload = stream.read(section["sh_size"])
            if section["sh_flags"] & 0x800:
                size = elf.structs.Elf_Chdr.sizeof()
                header = elf.structs.Elf_Chdr.parse(payload[:size])
                if header["ch_type"] == "ELFCOMPRESS_ZLIB":
                    payload = zlib.decompress(payload[size:])
                else:
                    assert header["ch_type"] == 2
                    with zstandard.ZstdDecompressor().stream_reader(
                        io.BytesIO(payload[size:]), read_across_frames=True
                    ) as reader:
                        payload = reader.read()
                assert len(payload) == header["ch_size"]
            result[section.name] = (section["sh_flags"], payload)
    return result


def set_compressed(path, names, enabled):
    with path.open("r+b") as stream:
        elf = ELFFile(stream)
        for index, section in enumerate(list(elf.iter_sections())):
            if section.name in names:
                flags = section["sh_flags"]
                flags = flags | 0x800 if enabled else flags & ~0x800
                stream.seek(elf["e_shoff"] + index * elf["e_shentsize"] + 8)
                stream.write(struct.pack(
                    ("<" if elf.little_endian else ">") + (
                        "Q" if elf.elfclass == 64 else "I"
                    ), flags
                ))


def replace_sections(source, output, replacements):
    with tempfile.TemporaryDirectory() as directory:
        command = ["llvm-objcopy"]
        for index, (name, data) in enumerate(replacements.items()):
            payload = pathlib.Path(directory) / str(index)
            payload.write_bytes(data)
            command.extend(["--update-section", f"{name}={payload}"])
        run(*command, str(source), str(output))


def prepare(directory):
    plain = directory / "plain"
    run("llvm-objcopy", "--compress-debug-sections=zlib", str(plain), str(directory / "zlib"))
    replacements = {}
    with plain.open("rb") as stream:
        elf = ELFFile(stream)
        encoding = "<" if elf.little_endian else ">"
        for name, (flags, data) in sections(plain).items():
            if flags & 2:
                continue
            # Split at a store hash, so a raw hash can survive without an
            # adjacent /nix/store prefix. Also cover Wild's multi-frame format.
            match = re.search(rb"/nix/store/([0-9a-z]{32})-", data)
            split = match.start(1) if match else len(data) // 2
            compressor = zstandard.ZstdCompressor(write_checksum=True)
            payload = compressor.compress(data[:split]) + compressor.compress(data[split:])
            if elf.elfclass == 64:
                header = struct.pack(encoding + "IIQQ", 2, 0, len(data), 1)
            else:
                header = struct.pack(encoding + "III", 2, len(data), 1)
            replacements[name] = header + payload
    replace_sections(plain, directory / "zstd", replacements)
    set_compressed(directory / "zstd", replacements, True)


def check(original, sanitized, source, sanitizer):
    source_hash = source.name.split("-", 1)[0].encode()
    assert len(source_hash) == 32
    for name in ["plain", "zlib", "zstd"]:
        before, after = original / name, sanitized / name
        if name != "zlib":
            assert source_hash in before.read_bytes(), name
        assert source_hash not in after.read_bytes(), name
        assert after.stat().st_mode & 0o777 == 0o555
        before_sections, after_sections = sections(before), sections(after)
        assert any(source_hash in data for _, data in before_sections.values())
        assert before_sections.keys() == after_sections.keys()
        for section, (flags, data) in before_sections.items():
            new_flags, new_data = after_sections[section]
            assert flags == new_flags
            if flags & 2:
                assert data == new_data
            else:
                assert len(data) == len(new_data)
                # Only fixed-length store-name hashes can change.
                expected = re.sub(
                    rb"(?<![0-9a-z])[0-9abcdfghijklmnpqrsvwxyz]{32}(?=-)",
                    b"e" * 32, data
                )
                assert new_data == expected, section
        # Actual native execution is confined to this locally built fixture.
        run(str(after))
        assert run("llvm-readelf", "-d", str(before), capture_output=True).stdout == (
            run("llvm-readelf", "-d", str(after), capture_output=True).stdout
        )
        # Decode the result independently and verify its DWARF structure.
        decoded = pathlib.Path(name + "-decoded")
        opaque = pathlib.Path(name + "-opaque")
        run("llvm-objcopy", str(after), str(opaque))
        opaque.chmod(0o600)
        names = {n for n, (flags, _) in after_sections.items() if flags & 0x800}
        set_compressed(opaque, names, False)
        replace_sections(opaque, decoded, {
            n: data for n, (flags, data) in after_sections.items() if not flags & 2
        })
        run("llvm-dwarfdump", "--verify", str(decoded))

    # The very same hash remains when it is real loadable data, even in an
    # allocated section whose name starts with ".debug_".
    allocated = pathlib.Path("allocated-reference")
    flags, payload = sections(original / "plain")[".debug_allocated"]
    assert flags & 2
    runtime_hash = re.search(rb"/nix/store/([0-9a-z]{32})-", payload).group(1)
    payload = payload.replace(runtime_hash, source_hash)
    replace_sections(original / "plain", allocated, {".debug_allocated": payload})
    run(sys.executable, str(sanitizer), str(allocated))
    assert sections(allocated)[".debug_allocated"][1] == payload
    assert source_hash in allocated.read_bytes()

    # Nor should a same-hash symbol-table entry be treated as a DWARF path.
    symbol = pathlib.Path("symbol-reference")
    run("llvm-objcopy", "--add-symbol", source_hash.decode() + "-symbol=.text:0",
        str(original / "plain"), str(symbol))
    run(sys.executable, str(sanitizer), str(symbol))
    with symbol.open("rb") as stream:
        assert source_hash in ELFFile(stream).get_section_by_name(".strtab").data()

    # Unknown compression must fail without changing the input.
    bad = pathlib.Path("unsupported")
    shutil.copyfile(original / "zstd", bad)
    with bad.open("r+b") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name(".debug_line")
        stream.seek(section["sh_offset"])
        stream.write(struct.pack(("<" if elf.little_endian else ">") + "I", 99))
    digest = hashlib.sha256(bad.read_bytes()).digest()
    result = subprocess.run([sys.executable, str(sanitizer), str(bad)])
    assert result.returncode != 0
    assert hashlib.sha256(bad.read_bytes()).digest() == digest


if sys.argv[1] == "prepare":
    prepare(pathlib.Path(sys.argv[2]))
else:
    check(*(pathlib.Path(arg) for arg in sys.argv[2:]))
