# pspdecrypt
A quick and *dirty* tool to decrypt PSP binaries, and also PSP updaters (PSAR format)

Licensed under GPLv3

Decryption code copied from [ppsspp](https://github.com/hrydgard/ppsspp/), making use of libkirk by draan

KL3E & KL4E implementation and PSAR extraction by artart78

## Usage
`pspdecrypt` is capable of decrypting `PRX` and `IPL` files as well as decyrpting and extracting `PSAR` archives and its contents, including IPL stages where possible.

## Release Notes
### 0.8
 * Adds KL3E & KL4E decompression support for PSAR contents
 * Adds `PSAR` support
 * Extracts most public FW, older JigKick payloads, and most TT FW
 
### Initial release (unversioned)
 * Decrypts `PRX` files
