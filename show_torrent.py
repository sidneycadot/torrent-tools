#! /usr/bin/env -S python3 -u

"""This script reads one or more torrent files and lists their content.

If so directed, the script will read the content of a downloaded version of the files described in each torrent,
and verify the content against the hashes that are part of the torrent file.
"""

import os
import argparse
import hashlib
from typing import Union, NamedTuple


def _decode_bencoded_data_recursive(bencoded_data: bytes, idx: int) -> tuple[int|list|dict|bytes, int]:
    """Recursively parse a bencoded byte sequence."""
    first_character = chr(bencoded_data[idx])
    match first_character:
        case 'i': # integer
            idx += 1
            end_of_integer_idx = bencoded_data.find(b'e', idx)
            if end_of_integer_idx == -1:
                raise ValueError("End-of-integer character not found.")
            value = int(bencoded_data[idx:end_of_integer_idx])
            return (value, end_of_integer_idx+1)
        case 'l': # list
            idx += 1
            decoded_list = []
            while chr(bencoded_data[idx]) != 'e':
                (value, idx) = _decode_bencoded_data_recursive(bencoded_data, idx)
                decoded_list.append(value)
            return (decoded_list, idx+1)
        case 'd': # dictionary
            idx += 1
            decoded_dict = {}
            while chr(bencoded_data[idx]) != 'e':
                (key, idx) = _decode_bencoded_data_recursive(bencoded_data, idx)
                if not isinstance(key, bytes):
                    raise ValueError("Expected string as dictionary key.")
                key_str = key.decode()
                (value, idx) = _decode_bencoded_data_recursive(bencoded_data, idx)
                decoded_dict[key_str] = value
            return (decoded_dict, idx+1)
        case _: # length-prefixed byte sequence
            colon_idx = bencoded_data.find(b':', idx)
            if colon_idx == -1:
                raise ValueError("Colon character not found.")
            size = int(bencoded_data[idx:colon_idx])
            decoded_bytes = bencoded_data[colon_idx+1:colon_idx+size+1]
            return (decoded_bytes, colon_idx+size+1)


def decode_bencoded_data(data: bytes) -> int|list|dict|bytes:
    """Parse a bencoded byte sequence."""
    (value, idx) = _decode_bencoded_data_recursive(data, 0)
    if idx != len(data):
        raise ValueError("Bad bencoded data.")
    return value


class TorrentVerificationError(Exception):
    """An error was found in the torrent file."""


class FileDescription(NamedTuple):
    name: str
    size: int


def process_torrent_file(torrent_filename: str, prefix_path: str, check_content: bool):
    """Process a given torrent file."""

    try:

        try:
            with open(torrent_filename, "rb") as fi:
                torrent_data_raw = fi.read()
        except FileNotFoundError:
            raise TorrentVerificationError("Torrent file not found, unable to process.".format(torrent_filename))

        torrent_data = decode_bencoded_data(torrent_data_raw)

        torrent_data_info = torrent_data["info"]

        # The toplevel "name" field is the filename (single file torrent) or directory name (multi-file torrent).
        torrent_data_info_name = torrent_data_info["name"].decode()

        if "files" in torrent_data_info:
            # The "info" dict has a "files" sub-dictionary, to handle multiple files.
            # In this case, 'torrent_data_info_name' is a directory prefix to be prepended to each of the file names.
            torrent_data_info_files = torrent_data_info["files"]
            file_descriptions = [FileDescription(os.path.join(torrent_data_info_name, file_info["path"][0].decode()), file_info["length"]) for file_info in torrent_data_info_files]
        else:
            # The "info" dict doesn't have a "files" sub-dictionary; the torrent describes a single file.
            # In this case, 'torrent_data_info_name' is the name of the single file.
            file_descriptions = [FileDescription(torrent_data_info_name, torrent_data_info["length"])]

        # Calculate total size of all data described by the torrent file.
        total_size = sum(file_description.size for file_description in file_descriptions)

        # Verify that the hashes specified have the expected size.
        piece_size = torrent_data_info["piece length"]
        torrent_data_info_piece_hashes = torrent_data_info["pieces"]

        single_piece_hash_size = 20  # SHA1 hash is 160 bits or 20 bytes.
        expected_torrent_data_info_piece_hashes_count = (total_size + piece_size - 1) // piece_size
        expected_torrent_data_info_piece_hashes_size = expected_torrent_data_info_piece_hashes_count * single_piece_hash_size

        if len(torrent_data_info_piece_hashes) != expected_torrent_data_info_piece_hashes_size:
            raise TorrentVerificationError("Bad length of torrent info piece hashes field (expected {} bytes, got {} bytes).".format(
                expected_torrent_data_info_piece_hashes_size, len(torrent_data_info_piece_hashes)))

        print("[{}] Torrent has {} files, {} bytes, piece size {} bytes.".format(torrent_filename, len(file_descriptions), total_size, piece_size))

        if not check_content:
            # Just list the contents of the torrent file; do not verify.
            for file_description in file_descriptions:
                print("[{}] File {}: {} bytes.".format(torrent_filename, file_description.name, file_description.size))
        else:
            # List and veridy the contents of the torrent file.

            torrent_data_info_piece_hashes_offset = 0
            piece = bytearray()

            # Read all files specified in the torrent.
            for file_description in file_descriptions:

                full_filename = os.path.join(prefix_path, file_description.name)
                #print("[{}] Verifying file {}: {} bytes.".format(torrent_filename, full_filename, file_description.size))

                try:
                    # Verify actual size of the file.
                    actual_size = os.stat(full_filename).st_size
                    if actual_size != file_description.size:
                        raise TorrentVerificationError("Actual file size ({}) does not correspond to the file size specified in the forrent file ({}).".format(
                            actual_size, file_description.size))

                    # Read the file, piece-by-piece, and verify pieces as they come in.
                    with open(full_filename, "rb") as fi:
                        while True:
                            missing = piece_size - len(piece)
                            fragment = fi.read(missing)
                            if len(fragment) == 0:
                                # End-of-file reached.
                                break
                            piece.extend(fragment)
                            assert len(piece) <= piece_size
                            if len(piece) == piece_size:
                                # We have a full piece.Verify its hash.
                                piece_hash = hashlib.sha1(piece).digest()
                                piece.clear()
                                if not torrent_data_info_piece_hashes.startswith(piece_hash, torrent_data_info_piece_hashes_offset):
                                    raise TorrentVerificationError("SHA1 hash mismatch for piece (file: {}).".format(full_filename))
                                torrent_data_info_piece_hashes_offset += single_piece_hash_size
                except FileNotFoundError:
                    raise TorrentVerificationError("File not found, unable to verify: {!r}".format(full_filename))

            # After processing all files specified in the torrent, we may have a trailing piece that needs to be hash-verified.
            if len(piece) != 0:
                # We have a trailing piece. Process it.
                piece_hash = hashlib.sha1(piece).digest()
                piece.clear()
                if not torrent_data_info_piece_hashes.startswith(piece_hash, torrent_data_info_piece_hashes_offset):
                    raise TorrentVerificationError("SHA1 hash mismatch for piece (file: {}).".format(full_filename))
                torrent_data_info_piece_hashes_offset += single_piece_hash_size

            # This assertion must be true given that we checked the correspondence between total_size, piece_size, and len(torrent_data_info_piece_hashes) before.
            assert torrent_data_info_piece_hashes_offset == len(torrent_data_info_piece_hashes)

            print("[{}] Successfully verified all {} pieces.".format(torrent_filename, expected_torrent_data_info_piece_hashes_count))

    except TorrentVerificationError as exception:
        print("[{}] Error: {}".format(torrent_filename, exception))

def main():

    parser = argparse.ArgumentParser(description="show information on torrent files.")

    parser.add_argument("--check-contents", "-c", action='store_true', help="verify hashes of data using local files (default: disabled)")
    parser.add_argument("--prefix-path", "-p", default="", help="path to local files, for hash verification (default: current working directory)")
    parser.add_argument("filenames", metavar="torrent-file", nargs="+", help = "torrent file to process")

    args = parser.parse_args()

    for filename in args.filenames:
        process_torrent_file(filename, args.prefix_path, args.check_contents)


if __name__ == "__main__":
    main()
