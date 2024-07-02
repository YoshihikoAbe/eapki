# eapki

EAPKI toolkit

# Usage

```
EAPKI toolkit

Usage:
  eapki [command]

Available Commands:
  dump        Dump the contents of an encrypted filesystem
  fcheck      Perform file integrity check
  help        Help about any command
  keyring     Create keyring dump
  obfuscate   Obfuscate or deobfuscate files used early in the eapki client's boot process (kbt.dll, etc...)
  p7e         Decrypt PKCS #7 encrypted files (kdm.dll, etc...)
  path        Convert a path/filename to an obfuscated drmfs path
  pins        List possible dongle pins
  proxy       Start authentication proxy

Flags:
  -h, --help   help for eapki

Use "eapki [command] --help" for more information about a command.
```

## Environment Variables

`PKCS11_MODULE`: Path to the PKCS11 module. If left blank, a platform specific default will be used instead.

## Dumping drmfs 

After connecting your license key, you can dump the contents of an encrypted filesystem by running `eapki dump SOURCE DESTINATION`.

After a successful dump, you may also perform a file check by running `eapki fcheck DESTINATION DESTINATION/prop/filepath.xml`.

## Decrypting Other Files

Some files are encrypted outside the context of drmfs, with the most notable of these being avs2-core.dll, avs2-ea3.dll, and bootstrap.xml.

Assuming that you have their respective bootstrap.exe file, you can decrypt these files by running `eapki obfuscate BOOTSTRAP FILES...`