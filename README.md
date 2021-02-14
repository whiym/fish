Fish
====

Fish is a Go implementation for IRC FiSH encryption. It uses the [Blowfish](x) cipher to encrypt/decrypt messages in
**EBC** and **CBC** modes based on a symmetric key. 

It calls ciphers from the Go standard library and sub-repositories, handles base64 encoding and irc message parsing.

The **EBC** implementation is based off the original 
[FiSH-irssi](https://web.archive.org/web/20110816103911/http://fish.secure.la/irssi/FiSH-irssi.v0.99-source.zip) source,
see [BASE64.md](BASE64.md) for an explanation of the unique base64 encoding scheme.

The **CBC** implementation is based off the extension of FiSH-irssi by
[falsovsky](https://github.com/falsovsky/FiSH-irssi) for compatibility with mircryption.

To use **CBC** mode the key must be prepended with `cbc:`
