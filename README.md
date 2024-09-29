# rustpwman

`rustpwman` is a simple password manager written in Rust using the [cursive TUI library](https://github.com/gyscos/cursive). You may wonder why someone writes a TUI 
application in 2024. The main reason is portability without creating a dependency to any of the usual GUI toolkits. `rustpwman` should work on macOS, Linux and Windows and 
it should compile without the necessity to install more or less exotic (or maybe even toxic) toolchains. Additionally I like the retro appeal of it and it can be used
over SSH.

# Building the software

Under Linux and macOS use `cargo build --release` to build with all features enabled. Under Windows you should call the batch file `build_win.bat` from a 
Visual Studio Developer prompt for this purpose. On top of that there is a separate section in this README that deals with building under Windows. If you want
a minimal set of features (and therefore a minimal set of dependencies) you can use `cargo build --release --no-default-features` under Linux, macOS and Windows.
In this case the password cache, support for WebDAV, additional crypto algorithms and the automatic local backup feature are not available.

If you have an older version of this repo on your  machine you need to perform a `cargo update` after pulling this release otherwise the official version 0.21 of 
cursive will not build. I am also using the as of today most current version 1.80 of `rustc`. 

# How to run the software

The basic concept of `rustpwman` is to manage a set of entries which have a value or content. The entries are presented in a flat list and no further structuring is offered at 
the moment. In order to start the program use

```
rustpwman gui -i <file_name>
```

or `cargo run --release -- gui -i <file_name>` which will result, after a successful password entry, in a window similar to this one.  

![](/screenshot.png?raw=true "Screenshot of rustpwman")

If the file specified through the `-i` parameter does not exist `rustpwman` will create a new data file using that name after you have supplied a suitable password.

# Getting help

Calling `rustpwman help` prints information about all available commands and produces the following output 

```
A password manager for the cursive TUI in Rust

Usage: rustpwman [COMMAND]

Commands:
  enc   Encrypt file
  dec   Decrypt file
  gui   Open file in TUI
  cfg   Change configuration
  gen   Generate passwords
  obf   Obfuscate WebDAV password
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help information
  -V, --version  Print version information
```

Use `rustpwman <command> -h` to get additional help for each command.

# Functionality of the `gui` command

This is the command you will use the most. It asks for a password and then presents the text user interface which allows you to manage the password data.

## The File menu
The `File` menu contains the following entries.

### Save file

Selecting this entry saves the encrypted data file using the password that was specified during program start or has been changed using `Change password`.

### Change password

Using this entry allows to select a new password which is used to encrypt the data file. After a new password has been selected the data file is saved 
automatically. The new password is also used in subsequent save operations. If `rustpwman` is compiled with the `pwmanclient`` feature then the password
cache is also automatically cleared, as the cached password is now incorrect.

### Cache password

Via this entry the password of the container can be cached in [`pwman`](https://github.com/rmsk2/pwman). This item is only present if `rustpwman` is compiled with the 
`pwmanclient` feature for the correct platform (see 'Optional Features' below).

### Clear cached password

When selecting this entry `rustpwman` attempts to remove a cached password from `pwman`. This item is only present if `rustpwman` is compiled with the `pwmanclient` feature.

### About

Shows an about dialog containing information about the author, the program version and the set of activated build features.

### Info

Shows how many entries are present in this data file, how it is accessed, where it is located and how it is encrypted. Additionally it is shown whether the password
is currently cached or not.

### Undo changes

When an entry is modified, added or deleted `rustpwman` retains information which allows to undo this modification. Selecting this menu entry opens a dialog which
allows to manually undo changes in the reverse order in which they were applied or to undo all unchages which have been recorded since the last time the data
file was saved.

### Quit and print

Selecting this entry ends the program and prints the value of the currently selected entry to the CLI window after the TUI has been closed. About the reasoning behind this idea have 
a look at the section [A note about using the clipboard](#a-note-about-using-the-clipboard). 

Tip: You can pipe the output of `rustpwman` to a program that places the data it reads via stdin in the clipboard. This works even under Windows which offers the `clip` 
command for this purpose. Under Linux `xsel` can be used and MacOS provides the `pbcopy` command. When you use `clip` under Windows you have to be aware that non ASCII
characters may not be displayed correctly when pasting the data copied by `clip.exe`. Alternatively you can use the `Copy to clipboard` menu entry for this purpose or 
use `paste_utf8.exe -c ` (see below) instead of `clip.exe`.

### Quit

Through this menu entry the program can be closed. Before ending the program it is checked if there are unsaved changes. If there are then the user is warned correspondingly and has the 
possibility to not end the program in order to save the changed state. 

## The Entry menu

This menu contains all operations that are supported with respect to entries. If any entry is modified then the title of the entry list is changed from `Entries` to `Entries *` until
the file is saved. I.e. if the header is `Entries *` then there are unsaved changes.

### Edit entry

This menu entry allows to manually edit the value or contents of the currently selected password entry. After the edit dialog opens you can additionally either generate a random 
password and insert it at the current cursor position or insert the current contents of the clipboard at that position.

![](/edit.png?raw=true "Screenshot of edit entry dialog")

When inserting a random password into the current entry the user has to specify some parameters which will influence the password generation process. One parameter is the 
security level in bits (of entropy). This describes how large the set of passwords should be from which the generator selects one at random. A security level of `k` bits 
means that there are `2**k` passwords to choose from. This parameter in essence determines the difficulty for an attacker when performing a brute force password search. 
The default security level is 80 bits but this can be changed by a config file (see below).

Additionally the user is able to select the set of characters which may appear in the randomly generated password. Currently the following alternatives are offered:

- Base64, where the potential padding character `=` is removed and the the special characters `/` and `+` are replaced by `$` and `!`
- Hex
- Numeric
- Special: This password generator aims to create pronouncable passwords which are constructed from the following elements: A sequence of two letter groups which consist of a consonant followed by a vowel. There are 420 such groups. Therefore when selecting one of these groups at random each one contains 8.7 bits of entropy. The final four character group is a consonant followed by a three digit number. There are 52*1000 such four character groups so it has an entropy of 15.6 Bits when one is chosen randomly.
- Custom: When selecting this option the user can customize the character set which is used to generate the password. What happens here is in essence a radix conversion of a random binary number, which has the selected number of bits, into the base which is derived from the number `N` of unique characters in the custom character set. Each character in that set is then used as a base `N` digit. While the security level of the generated password is guaranteed to be equal to the selected value it has to be noted that this does not mean that all digits appear in all positions with equal probability.

![](/custom.png?raw=true "Screenshot of password generation dialog")

The controls to select a custom character set are hidden unless you select the `custom` option. According to the Rust documentation the random number generator underlying the whole process is a *thread-local CSPRNG with periodic seeding from OsRng. Because this is local, it is typically much faster than OsRng. It should be secure, though the paranoid may prefer OsRng*.

### Copy to clipboard

This menu entry can be used to copy the value of the currently selected password entry to the clipboard. For the reasons described [below](#a-note-about-using-the-clipboard) this 
feature requires an additional tool which accepts its input via stdin and uses that data to set the clipboard contents. The path to this tool can be confgured by calling
`rustpwman cfg`. When you use `clip.exe` under Windows for this purpose you have to be aware that non ASCII characters may not be displayed correctly after pasting the clipboard
data. The reason for this is that `clip.exe` expects a character encoding different from UTF-8 which is the default for Rust. If you want to prevent this problem you can use
`paste_utf8.exe -c` instead of `clip.exe`.

### Add entry

Select this menu item to create a new password entry and edit its contents.

### Delete entry 

Use this menu entry to delete the currently selected password entry. Before deleting the entry the user is prompted whether the entry is really to be deleted. 

### Rename entry 

Via this menu entry the currently selected entry can be renamed. It is not allowed to use the empty string as a new name. rustpwman also checks that no entry having the new name already exists.

### Clear entry

Via this menu entry the contents of the currently selected password entry can be cleared. As with deletion the user is prompted for confirmation before the contents is cleared.

### Load entry

This allows to load the contents of a (text-)file into an entry. The current contents of the entry is overwritten.

# A note about using the clipboard

It has to be noted that copying and pasting text in its most basic form is not possible in a terminal window while the cursive application is running. This in turn is probably 
an unfixable problem as cursive by definition controls the cursor in the terminal window, which most likely precludes the OS from "doing its thing". 

`rustpwman` works around this problem in three ways. At first pasting from the clipboard is emulated by spawning a new process in which a command is executed that writes the clipboard contents to stdout. `rustpwman` can then read the output of that process and write it into the TUI. `rustpwman` expects that the data to be read from stdout is UTF-8 encoded.

Secondly copying to the clipboard is possible as soon as `rustpwman` has stopped. When selecting `Quit and print` from the main menu `rustpwman` is stopped and the contents of the currently selected entry is printed to the terminal window. The necessary information can now be copied from the terminal into the clipboard and pasted where needed.

The third implemented option is the possibility to copy an entry as a whole to the clipboard by spawning a process that runs a program which is able to transfer the data it
receives via stdin to the clipboard. As Rust uses the UTF-8 character encoding this works best when the tool used for this purpose also expects its data in UTF-8.

As an additional workaround there is a possibility to load data from a file into an existing entry using the `Load entry` menu entry.

# Configuration or the functionality of the `cfg` command

Rustpwman uses a TOML config file for setting the default security level for newly generated passwords, the default password generator, 
the default PBKDF, CLI commands which can be used to set and retrieve the contents of the clipboard and optionally the parameters needed
for a WebDAV connection. The most convenient way to edit the config file is to use the `rustpwman cfg` command which will open a window 
similar to this one

![](/scrshot_cfg.png?raw=true "Screenshot of rustpwman cfg")

This screenshot was taken while running a version which was compiled with the `webdav` feature. Here is an example for `rustpwman` configuration file:

```
[defaults]
seclevel = 18
pbkdf = "argon2"
pwgen = "special"
clip_cmd = "xsel -ob"
copy_cmd = "xsel -ib"
webdav_user = ""
webdav_pw = ""
webdav_server = ""
```

- `seclevel` has to be an integer between 0 and 23. The security level in bits is calculated as (`seclevel` + 1) * 8. 
- `pbkdf` is a string that can assume the values `scrypt`, `argon2`, `sha256`
- `pwgen` is one of the strings `base64`, `hex`, `numeric` or `special`
- `clip_cmd` is a string which specifies a command that can be used to write the current contents of the clipboard to stdout. 
- `copy_cmd` is a string which specifies a command that can be used to transfer the data sent to it via stdin to the clipboard. 
- See below for an explanation of  the `webdav_xx` entries.

The default value for `clip_cmd` is `xsel -ob`, which works on Linux to retrieve the contents of the clipboard, which is filled via `CTRL+C` or after activating the `Copy` 
item from the context menu. If you want to use the primary selection, where text only has to be selected and not explicitly copied then use `xsel -op`. Remark: I had 
to manually install `xsel` on Ubuntu 22.04. Under MacOS `pbpaste -Prefer txt` can be used. For usage under Windows `rustpwman` provides the ("slightly" overengineered ;-))
tool `paste_utf8.exe` which can be built in a Visual Studio developer prompt using the `build_paste_utf8.bat` batch file.

The value `copy_cmd` uses `xsel -ib` as a default. This should work under Linux. Use `pbcopy` under MacOS and `clip.exe` or `paste_utf8.exe -c` under Windows.

The config file is stored in the users' home directory in a file named `.rustpwman` and you can alternatively edit it by hand instead of calling `rustpwman cfg`. 

# Using `rustpwman` to generate passwords or the `gen` command

When you run the `rustpwman gen` command you can generate one or more passwords without opening a password file. Here a screenshot of the TUI:

![](/gen_command.png?raw=true "Screenshot of rustpwman gen")

Tip: You can pipe the output of `rustpwman gen` into a program that copies the data it receives via stdin into the clipboard.

# Using `rustpwman` to en- decrypt files or the `enc` and `dec` commands

`rustpwman enc` and `rustpwman dec` can be used to en- and decrypt arbitrary files even though their main purpose is to allow you to decrypt your password data under
one PBKDF or cipher and reencrypt that data using another key derivation function or cipher in case you want to migrate from one PBKDF or cipher to another. On top of 
that the decrypted password data can be used to export all data from `rustpwman` in a form which can be processed by other software. Additionally if you are able to 
create a JSON file of the form described [below](#format-of-payload-data) you can import data from another password manager.

# Optional features

## Password cache

Beginning with version 1.2.0 `rustpwman` is being built with support for the password cache implemented in [`pwman`](https://github.com/rmsk2/pwman). This feature can be
disabled by issuing the command `cargo build --release --no-default-features` on all supported platforms. When the feature is active `rustpwman` attempts to read the 
password for the data file specified by the `-i` option from the cache provided by `pwserv`.

If this does not succeed, the user is requested to enter a password as was the case in Version 1.1.0 and below. If on the other hand the password was successfully read, the 
user is asked to confirm that it should be used. Through the correspondig dialog the user is also able to clear the password from the cache. This can come in handy when
the cached password does not match the current password of the file which is to be opened.

Depending on the platform for which `rustpwman` is being built the feature is named `pwmanclientux` (Linux and MacOS) or `pwmanclientwin` (Windows).

## WebDAV support

If you build `rustpwman` with the optional `webdav` feature enabled you can access password data files on WebDAV shares without explicitly mounting the share first. This `rustpwman` 
feature has been successfully tested against a well known cloud storage provider using TLS. The credentials are read from the `.rustpwman` config file using the following entries:

```
....
webdav_user = "user"
webdav_pw = "password"
webdav_server = "http://server.test.com/davtest/"
```

The entry `webdav_server` can be set to the empty string because it and the value supplied with  the `-i` option are concatenated to form the store location. If this location 
starts with `http` then `rustpwman` assumes that a WebDAV share is to be accessed. Otherwise it is expected that the password file resides in the file system. 

The WebDAV password can optionally be stored in an obfuscated way. For this to work the environment variable `RUSTPWMAN_OBFUSCATION` has to be
set to a random value which is then used to encrypt and decrypt the password. Encrypted passwords have to have the prefix `##obfuscated##:`. A 
de obfuscation is only attempted if the environment variable is set **and** the `webdav_pw` value in the config file starts with the above 
mentioned prefix. Obfuscation of a plaintext password can be performed via the `rustpwman obf` command. When executing this command the
user has to enter the password twice and then the obfuscated version is printed to the screen from where it can be copied to the `.rustpwman`
config file. Alternatively the password can be obfuscated via the `rustpwman cfg` command. It has to be noted that this system of obfuscation 
only stops the most casual of attackers.

Even though any WebDAV share can be mounted in such a way that it appears as a local drive this feature is in my view worth the additional about 50 dependencies, as it
saves you the mouse clicks to actually mount the WebDAV share.

Additional note: Under Linux you have to install the package `libssl-dev` when compiling with this feature as the TLS implementation of the `reqwest` library seems to 
depend on it being present.

## Support for ChaCha20 Poly-1305 and AES-192 GCM

When you build `rustpwman` with the `chacha20` feature you can use ChaCha20 Poly-1305 or AES-192 GCM as an alternative cipher for password file encryption. These algorithms are 
activated by setting the environment variable `PWMANCIPHER` to a value. If the variable is set to the value `AES192` or `AES256` then AES-192 or AES-256 GCM will be used. Any other 
value makes `rustpwman` using ChaCha20 Poly-1305. If the variable is not set when `rustpwman` is started, then AES-256 GCM is used. Under Linux and MacOS you can for instance use 
`PWMANCIPHER=CHACHA20 rustpwman gui -i input_file.enc` to set the environment varible and start `rustpwman` in one go. 

As an alternative to setting an environment variable you can also use the `--cipher` or `-c` command line option and one of the parameters
`aes256`, `aes192` or `chacha20` to determine the cipher which is used by `rustpwman`. This option works with the `enc`, `dec` and
the `gui` command. This may serve as an example: `rustpwman gui -i input_file.enc -c chacha20`. 

ChaCha20 Poly-1305 provides security comparable to AES-256 GCM and so it comes down to a matter of taste which cipher you use. Even though AES-192 has a shorter key than AES-256
a key length of 192 bits should still be past anyones paranoia level. On top of that it is very unlikely that you use a password with a 192 bit or higher entropy to derive 
the encryption key used by `rustpwman` in the first place. There are even some (more theoretical) attacks which affect AES-192 less than AES-256 so if you want to use it, here it is.

## Automatic local backup of last successfully opened password file

I mostly use `pwman` to access a password file which resides on a WebDAV share stored at a cloud provider. This is all fine and dandy as long as one can access cloud resources.
This may not be the case at times when there is no internet connection or if the cloud provider is offline. If the feature `writebackup` is active `rustpwman` stores a local copy 
of the data file after its password has been successfully verified. As a default the backup file is stored in the current directory using the name `rustpwman_last.enc`. This
default can be overriden by setting the environment variable `PWMANBKP` to the desired name of the backup file. This feature is active by default.

# Rustpwman under Windows

## Native

The good news is that it works and it even works well. I have tested the `pancurses` backend of `cursive` under Windows. The [`pancurses`](https://github.com/ihalila/pancurses) backend 
uses a binding to a C library and requires an [installed C compiler](https://github.com/ihalila/pdcurses-sys) in order to build. On the other hand Rust itself is dependent on a C 
compiler when used under Windows. 

In order to build `rustpwman` with all optional features you have to use the command `cargo build --release --no-default-features --features pwmanclientwin,chacha20,webdav`. 
Alternatively you can call the batch file `build_win.bat` which executes this command and calls `build_paste_utf8.bat` (see below). If you do not care about the 
password cache, WebDAV or the additional ciphers use `cargo build --release --no-default-features`. You should additionally build the `paste_utf8.exe` tool by 
running `build_paste_utf8.bat` in a Visual Studio developer prompt. This tool enables you to paste the clipboard contents while editing an entry and to copy an entry which
contains non-ASCII characters (in my case Umlauts) to the clipboard in such a way that the non ASCII characters are displayed correctly.

This batch file also builds `winfilter.exe` from the rust source `winfilter.rs`. This tool copies its stdin to stdout while filtering out the Escape sequence `ESC[?1002l` from its 
input (if it appears at the beginning of the stream). Therefore if you pipe the output of `rustpwman` through `winfilter.exe` you can cleanup `rustpwman`'s output in order to
make further processing easier.

I have tested `rustpwman` with the `pancurses` backend in the normal `cmd.exe` console and the new [Windows Terminal](https://www.microsoft.com/en-us/p/windows-terminal/9n0dx20hk701#activetab=pivot:overviewtab). Both work well. It has to be noted though that the `pancurses` version does not run in the console window from which it was started:
It opens a new window. On top of that this window, let's call it the `pancurses` window, remembers its size from session to session. You can change the font type and size which
is used if you right click on the title bar of the `pancurses` window.

## Windows Subsystem for Linux (WSL)

As expected, building `rustpwman` for WSL works without problems after installing all dependencies like `git`, `gcc`, `libssl-dev` and `libncurses`. The resulting 
application also works but there is a perceptible decrease in performance (TUI flickers a bit when updating the screen) when compared to the native version which uses the 
`pancurses` backend.

# Some technical information

## About the crypto

As a default `rustpwman` encrypts its data at rest using AES-256 GCM with a 128 bit tag length and a 96 bit nonce. If the feature `chacha20` is active when `rustpwman` is built
then ChaCha20 Poly-1305 or AES-192 GCM can be used as an alternative. Obviously a ChaCha20 or AES-192 encrypted file can not be decrypted by a `rustpwman` version which uses 
AES-256 GCM only. The encrypted data file is a simple JSON data structure. This may serve as an example:

```
{
  "PbKdf": "argon2",
  "Salt": "+w1dzd7gyIaR/iBvJJCU5Q==",
  "Nonce": "GqPy617WwqiP2Aha",
  "Data": "4YM5XNvMou3TukBnYCRCMoAhia2jaoBfyRIr+aGJ0dTrZTtiah4dm6W8gKnmt95/mDPBx2E+5Hy8cxz
  ef4vOM0vTjy/2H9EFgpO5m7onxJTzBOgjqtnE4lH6vLiYJ+FN6GW+68Y1X7OgifCln8nP4D++u4vJnZEYgiAMB7Y
  rjdvP7Evp4fHcx6/B/LM1ga7Cg4T57/a8SG7wK7hlBY+CUoVH9HKjzEZAMPyuyai/ZQMjgG1w9Bpn5zNnjntTn/K
  +y0hX209VTiEPK43DO/3d05tPrJfmkJNUsjskTn2teANooIlo9ZG1YMCNxe/r0ns8YPJEAlgS2R5HSNBodqgIiFc
  qQ9mSuta4iwaBG+DAZ5KHmVooLZ+L0djsgKtbEGVjjIVsaO/qFZpx"
}
 ```

As a default the actual encryption key is derived from the entered password using the `Argon2id` key derivation function. `rustpwman` also allows to alternatively use `scrypt` 
or to derive the key from the specified password using the following calculation:

```
SHA-256( password | salt | password )
```

where `salt` is a random value and `|` symbolizes concatenation. It is also possible to select this or another password based key derivation function 
(PBKDF) through the `--kdf` option or by a config file. Currently `scrypt`, `argon2` and `sha256` are valid as a parameter for this option and as a config 
file entry. As a source for the PBKDF parameter choices https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html has been used. The
salt length is always 128 bit.

## Format of payload data

The plaintext password data is simply stored as key value pairs in an obvious way using JSON. There is not much more to know than shown in this example: 

```
[
  {
    "Key": "test2",
    "Text": "first test \n"
  },
  {
    "Key": "test42",
    "Text": "second test \n"
  }
]
```

Due to this extreme simplicity the password files created by `rustpwman` are really compact. The file which holds my passwords (having about 50 entries) is less than 16 KB in 
size.

# Caveats

This section provides information about stuff which is in my view suboptimal and the user should be aware of:

- At the moment I do not attempt to overwrite memory that holds sensitive information when `rustpwman` is closed. This may be a problem when `rustpwman` is used in an environment where an attacker can gain access to memory previously used by `rustpwman`, i.e. when sharing a machine with an attacker.
- When the list of entries changes (after an add or delete) it may be possible that the entry selected after the change is not visible in the `ScrollView` on the left. I was not successfull in forcing cursive to scroll to the newly selected entry. This is most probably my fault and meanwhile an appropriate warning dialog is displayed.
- I am fairly new to Rust. I guess it shows in the code.
- On MacOS using the mouse scroll wheel or the Page Up/Down keys to select an entry confuses cursive. This does not happen on Linux or Windows.
- On Windows a spurious Escape sequence `ESC[?1002l` is printed to stdout when the TUI application stops. This does not happen on Linux or MacOS. By piping the output of `rustpwman` to `winfilter.exe` you can remove this unwanted data from the output.
- In non `--release` builds scrypt with the chosen parameters is *extremely* slow

