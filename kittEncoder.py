import sys
import re

words = [
    "floof",
    "purrito",
    "meow",
    "blepp",
    "boop",
    "zoomies",
    "mlem",
    "loaf",
    "chonk",
    "nap",
    "catnip",
    "whisker",
    "paws",
    "tail",
    "mittens",
    "kitteh",
]


def extract_shellcode(content):
    match = re.search(r'"(.*?)"', content, re.DOTALL)
    if match:
        return match.group(1)
    else:
        raise ValueError("No shellcode found between quotes in the input file.")


def parse_shellcode(shellcode_str):
    hex_values = shellcode_str.replace(" ", "").split("\\x")
    return bytes([int(x, 16) for x in hex_values if x])


def encode_shellcode(shellcode):
    encoded = []
    for byte in shellcode:
        high_nibble = (byte >> 4) & 0x0F
        low_nibble = byte & 0x0F
        encoded.append(f"{words[high_nibble]}-{words[low_nibble]}")
    return " ".join(encoded)


def decode_shellcode(encoded):
    word_to_nibble = {word: i for i, word in enumerate(words)}
    decoded = bytearray()
    current_byte = 0
    is_high_nibble = True
    
    for word in encoded.replace("-", " ").split():
        nibble = word_to_nibble[word]
        if is_high_nibble:
            current_byte = nibble << 4
        else:
            current_byte |= nibble
            decoded.append(current_byte)
        is_high_nibble = not is_high_nibble
    return bytes(decoded)


def format_shellcode(shellcode):
    return "".join(f"\\x{byte:02x}" for byte in shellcode)


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: python script.py <input_file> <encoded_output_file> <decoded_output_file>"
        )
        sys.exit(1)
    input_file = sys.argv[1]
    encoded_output_file = sys.argv[2]
    decoded_output_file = sys.argv[3]
    
    try:
    
        with open(input_file, "r") as f:
            file_content = f.read()
        shellcode_str = extract_shellcode(file_content)
        shellcode = parse_shellcode(shellcode_str)
        encoded_shellcode = encode_shellcode(shellcode)
        
        with open(encoded_output_file, "w") as f:
            f.write(encoded_shellcode)
        print(f"Shellcode encoded and saved to {encoded_output_file}")
        decoded_shellcode = decode_shellcode(encoded_shellcode)
        
        formatted_shellcode = format_shellcode(decoded_shellcode)
        with open(decoded_output_file, "w") as f:
            f.write(formatted_shellcode)
        print(f"Shellcode decoded and saved to {decoded_output_file} in \\x format")
        
    except IOError as e:
        print(f"Error reading or writing file: {e}")
        sys.exit(1)
        
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
