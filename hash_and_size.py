import os
import sys
import struct
import hashlib

def extract_expected_values_from_apk(apk_path: str):
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"File not found: {apk_path}")

    file_size = os.path.getsize(apk_path)

    with open(apk_path, 'rb') as fp:
        # 1. Поиск End of Central Directory (EOCD)
        eocd_found = False
        cd_offset = 0

        # Эквивалент цикла: for (i = 0;; ++i) ... pos = generic_file_llseek(fp, -i - 2, SEEK_END);
        for i in range(0x10000):
            if file_size < i + 2:
                break

            fp.seek(file_size - i - 2)
            n = struct.unpack('<H', fp.read(2))[0]

            if n == i:
                fp.seek(file_size - i - 22)
                size4 = struct.unpack('<I', fp.read(4))[0]

                # Эквивалент: if ((size4 ^ 0xcafebabeu) == 0xccfbf1eeu)
                # 0x06054b50 ^ 0xcafebabe = 0xccfbf1ee
                if size4 == 0x06054b50:
                    # Эквивалент: pos += 12; kernel_read(fp, &size4, 0x4, &pos);
                    fp.seek(file_size - i - 6)
                    cd_offset = struct.unpack('<I', fp.read(4))[0]
                    eocd_found = True
                    break

        if not eocd_found:
            raise ValueError("error: cannot find eocd")

        # 2. Проверка наличия APK Sig Block 42
        # Эквивалент: pos = size4 - 0x18; kernel_read(fp, &size8, 0x8, &pos);
        fp.seek(cd_offset - 0x18)
        size8 = struct.unpack('<Q', fp.read(8))[0]

        # Эквивалент: kernel_read(fp, buffer, 0x10, &pos);
        buffer = fp.read(16)
        if buffer != b"APK Sig Block 42":
            raise ValueError("APK Sig Block 42 not found")

        # 3. Чтение и валидация размера блока
        # Эквивалент: pos = size4 - (size8 + 0x8); kernel_read(fp, &size_of_block, 0x8, &pos);
        fp.seek(cd_offset - (size8 + 0x8))
        size_of_block = struct.unpack('<Q', fp.read(8))[0]
        if size_of_block != size8:
            raise ValueError("size_of_block != size8")

        # 4. Обход блоков (поиск v2 signature block)
        loop_count = 0
        while loop_count < 10:
            loop_count += 1

            # Эквивалент: kernel_read(fp, &size8, 0x8, &pos); // sequence length
            sequence_length = struct.unpack('<Q', fp.read(8))[0]
            if sequence_length == size_of_block:
                break

            # Эквивалент: kernel_read(fp, &id, 0x4, &pos); // id
            block_id = struct.unpack('<I', fp.read(4))[0]

            # 0x7109871au - APK Signature Scheme v2
            if block_id == 0x7109871a:
                # =================== check_block логика ===================
                # Эквивалент 3х kernel_read для длин sequence / signer / signed data
                signer_seq_len = struct.unpack('<I', fp.read(4))[0]
                signer_len = struct.unpack('<I', fp.read(4))[0]
                signed_data_len = struct.unpack('<I', fp.read(4))[0]

                # Эквивалент: kernel_read(fp, size4, 0x4, pos); // digests-sequence length
                digests_seq_len = struct.unpack('<I', fp.read(4))[0]

                # Эквивалент: *pos += *size4;
                fp.seek(digests_seq_len, os.SEEK_CUR)

                # Эквивалент: kernel_read для certificates length и certificate length
                certs_len = struct.unpack('<I', fp.read(4))[0]
                cert_len = struct.unpack('<I', fp.read(4))[0] # Это искомый expected_size

                # Эквивалент: kernel_read(fp, cert, *size4, pos);
                cert = fp.read(cert_len)

                # Эквивалент ksu_sha256 и bin2hex
                expected_size = cert_len
                expected_hash = hashlib.sha256(cert).hexdigest()

                return expected_size, expected_hash

            # Эквивалент: pos += (size8 - offset); // offset = 4 (размер id)
            fp.seek(sequence_length - 4, os.SEEK_CUR)

    raise ValueError("v2 signing valid block not found")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_apk>")
        sys.exit(1)

    apk_file = sys.argv[1]

    try:
        size, sha256_hex = extract_expected_values_from_apk(apk_file)
        print(f"EXPECTED_SIZE = \"{size}\"")
        print(f"EXPECTED_HASH = \"{sha256_hex}\"")
    except Exception as e:
        print(f"Error processing APK: {e}")
        sys.exit(1)
