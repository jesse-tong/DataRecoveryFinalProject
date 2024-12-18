import sys

# Define signatures
PNG_START = b"\x89PNG\r\n\x1a\n"
PNG_END_CHUNK = b"IEND"
JPG_START = b"\xff\xd8\xff"
JPG_END = b"\xff\xd9"

def find_all_occurrences(data, signature):
    """Return a list of all indexes at which the signature occurs in data."""
    start = 0
    occurrences = []
    while True:
        idx = data.find(signature, start)
        if idx == -1:
            break
        occurrences.append(idx)
        start = idx + 1
    return occurrences

def recover_jpegs(data):
    """Recover JPEG files from the binary data."""
    jpegs = []
    start_positions = find_all_occurrences(data, JPG_START)
    for start_pos in start_positions:
        end_pos = data.find(JPG_END, start_pos + len(JPG_START))
        if end_pos != -1:
            # Include the end marker
            end_pos += len(JPG_END)
            jpegs.append(data[start_pos:end_pos])
    return jpegs

def recover_pngs(data):
    """Recover PNG files from the binary data."""
    pngs = []
    start_positions = find_all_occurrences(data, PNG_START)
    for start_pos in start_positions:
        # Find IEND chunk. The IEND chunk is always 12 bytes: 
        # 4-byte length (0x00000000), 4-byte chunk type ('IEND'), 4-byte CRC.
        # We'll search for 'IEND' and then add 8 bytes total (4 for length & 4 for CRC)
        iend_pos = data.find(PNG_END_CHUNK, start_pos)
        if iend_pos != -1:
            # The end of PNG will be at iend_pos + 4 (chunk type) + 4 (CRC) = iend_pos + 8
            end_pos = iend_pos + 8
            pngs.append(data[start_pos:end_pos])
    return pngs

def main():
    # Open the volume file
    filename = "Image00.Vol.vhd"
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[-] {filename} not found.")
        sys.exit(1)

    # Recover JPG and PNG files
    recovered_jpgs = recover_jpegs(data)
    recovered_pngs = recover_pngs(data)

    # Write recovered JPG files
    jpg_count = 0
    for jpg_data in recovered_jpgs:
        out_name = f"Recovered_{jpg_count:03d}.jpg"
        with open(out_name, "wb") as out:
            out.write(jpg_data)
        print(f"[+] Recovered JPEG: {out_name}")
        jpg_count += 1

    # Write recovered PNG files
    png_count = 0
    for png_data in recovered_pngs:
        out_name = f"Recovered_{png_count:03d}.png"
        with open(out_name, "wb") as out:
            out.write(png_data)
        print(f"[+] Recovered PNG: {out_name}")
        png_count += 1

    print("[+] Recovery complete!")
    print(f"    Recovered {jpg_count} JPEG(s) and {png_count} PNG(s).")

if __name__ == "__main__":
    main()