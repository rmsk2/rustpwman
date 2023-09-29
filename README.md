# rustpwman

`rustpwman` is a simple password manager written in Rust using the [cursive TUI library](https://github.com/gyscos/cursive). You may wonder why someone writes a TUI 
application in 2023. The main reason is portability without creating a dependency to any of the usual GUI toolkits. `rustpwman` should work on MacOS, Linux and Windows and 
it should compile without the necessity to install more or less exotic (or maybe even toxic) toolchains. Additionally I like the retro appeal of it.

# Introduction

The basic concept of `rustpwman` is to manage a set of entries which have a value or content. The entries are presented in a flat list and no further structuring is offered at 
the moment. In order to start the programm use

```
rustpwman gui -i <file_name>
```

or `cargo run --release -- gui -i <file_name>` which will result, after a successful password entry, in a window similar to this one.  

![](/screenshot.png?raw=true "Screenshot of rustpwman")

If the file specified through the `-i` parameter does not exist `rustpwman` will create a new data file using that name after you have supplied a suitable password.

## About the crypto

`rustpwman` encrypts its data at rest using AES-256 in GCM mode with a 128 bit tag length and a 96 bit nonce. The encrypted data file is a simple JSON data structure. 
This may serve as an example:

```
{
  "PbKdf": "sha256",
  "Salt": "/qcBaihI/4wV1A==",
  "Nonce": "t8RCYaLY3Bsisl5K",
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

where `salt` is a random value of appropriate length and `|` symbolizes concatenation. It is also possible to select this or another password based key derivation function 
(PBKDF) through the `--kdf` option or by a config file. Currently `scrypt`, `argon2` and `sha256` are valid as a parameter for this option and as a config 
file entry. As a source for the PBKDF parameter choices https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html has been used.

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

Using this entry allows to select a new password. After a new password has been selected the encrypted data file is saved automatically. The new password is also used in 
subsequent save operations. If `rustpwman` is compiled with the pwmanclient feature then the password cache is also automatically cleared, as the cached password is now 
incorrect.

### Cache password

Via this entry the password of the container can be cached in [`pwman`](https://github.com/rmsk2/pwman). This item is only present if `rustpwman` is compiled with the 
pwmanclient feature for the correct platform (see 'Optional Features' below).

### Clear cached password

When selecting this entry `rustpwman` attempts to remove a cached password from `pwman`. This item is only present if `rustpwman` is compiled with the pwmanclient feature.

### About

Shows an about dialog containing information about the author and the program version.

### Quit and print

Selecting this entry ends the program and prints the value of the currently selected entry to the CLI window after the TUI has been closed. About the reasoning behind this idea have 
a look at the section [A note about using the clipboard](#a-note-about-using-the-clipboard). 

Tip: You can pipe the output of `rustpwman` to a program that places the data it reads via stdin in the clipboard. This works even under Windows which offers the `clip` 
command for this purpose. Under Linux `xsel` can be used and MacOS provides the `pbcopy` command. When you use `clip` under Windows you have to be aware that non ASCII
characters may not be displayed correctly when pasting the data copied by `clip`.

### Quit

Through this menu entry the program can be closed. Before ending the program it is checked if there are unsaved changes. If there are then the user is warned correspondingly and has the 
possibility to not end the program in order to save the changed state. 

## The Entry menu

This menu contains all operations that are supported with respect to entries.

### Edit entry

This menu entry allows to manually edit the value or contents of the currently selected password entry. After the edit dialog opens you can additionally either generate a random 
password and insert it at the current cursor position or insert the current contents of the clipboard at that position.

When inserting a random password into the current entry the user has to specify some parameters which will influence the password generation process. One parameter is the 
security level in bits (of entropy). This describes how large the set of passwords should be from which the generator selects one at random. A security level of `k` bits 
means that there are `2**k` passwords to choose from. This parameter in essence determines the difficulty for an attacker when performing a brute force password search. 
The default security level is 80 bits but this can be changed by a config file (see below).

Additionally the user is able to select the set of characters which may appear in the randomly generated password. Currently the following alternatives are offered:

- Base64, where the potential padding character `=` is removed and the the special characters `/` and `+` are replaced by `$` and `!`
- Hex
- Special: This password generator aims to create pronouncable passwords which are constructed from the following elements: A sequence of two letter groups which consist of a consonant followed by a vowel. There are 420 such groups. Therefore when selecting one of these groups at random each one contains 8.7 bits of entropy. The final four character group is a consonant followed by a three digit number. There are 52*1000 such four character groups so it has an entropy of 15.6 Bits when one is chosen randomly.

According to the Rust documentation the random number generator underlying the whole process is a *thread-local CSPRNG with periodic seeding from OsRng. Because this is local, it is typically much faster than OsRng. It should be secure, though the paranoid may prefer OsRng*.

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

`rustpwman` works around this problem in two ways. At first pasting from the clipboard is emulated by spawning a new process in which a command is executed that writes the clipboard contents to stdout. `rustpwman` can then read the output of that process and write it into the TUI. `rustpwman` expects that the data to be read from stdout is UTF-8 encoded.

Secondly copying to the clipboard is possible as soon as `rustpwman` has stopped. When selecting `Quit and print` from the main menu `rustpwman` is stopped and the contents of the currently selected entry is printed to the terminal window. The necessary information can now be copied from the terminal into the clipboard and pasted where needed.

As an additional workaround there is a possibility to load data from a file into an existing entry using the `Load entry` menu entry.

# Configuration or the functionality of the `cfg` command

Rustpwman uses a TOML config file for setting the default security level for newly generated passwords, the default password generator, the default PBKDF 
and a CLI command which can be used to retrieve the contents of the clipboard. The most convenient way to edit the config file is to use the `rustpwman cfg` 
command which will open a window similar to this one

![](/scrshot_cfg.png?raw=true "Screenshot of rustpwman cfg")

Here is an example for `rustpwman` configuration file:

```
[defaults]
seclevel = 18
pbkdf = "argon2"
pwgen = "special"
clip_cmd = "xsel -ob"
```

- `seclevel` has to be an integer between 0 and 23. The security level in bits is calculated as (`seclevel` + 1) * 8. 
- `pbkdf` is a string that can assume the values `scrypt`, `argon2`, `sha256`
- `pwgen` is one of the strings `base64`, `hex` or `special`
- `clip_cmd` is a string which specifies a command that can be used to write the current contents of the clipboard to stdout. 

The default value for `clip_cmd` is `xsel -ob`, which works on Linux to retrieve the contents of the clipboard, which is filled via `CTRL+C` or after activating the `Copy` 
item from the context menu. If you want to use the primary selection, where text only has to be selected and not explicitly copied then use `xsel -op`. Remark: I had 
to manually install `xsel` on Ubuntu 22.04. Under MacOS `pbpaste -Prefer txt` can be used. For usage under Windows `rustpwman` provides the ("slightly" overengineered ;-))
tool `paste_utf8.exe` which can be built in a Visual Studio developer prompt using the `build_paste_utf8.bat` batch file.

The config file is stored in the users' home directory in a file named `.rustpwman` and you can alternatively edit it by hand instead of calling `rustpwman cfg`. 

# Using `rustpwman` to generate passwords or the `gen` command

When you run the `rustpwman gen` command you can generate one or more passwords without opening a password file. Here a screenshot of the TUI:

![](/gen_command.png?raw=true "Screenshot of rustpwman gen")

Tip: You can pipe the output of `rustpwman gen` into a program that copies the data it receives via stdin into the clipboard.

# Using `rustpwman` to en- decrypt files or the `enc` and `dec` commands

`rustpwman enc` and `rustpwman dec` can be used to en- and decrypt arbitrary files even though their main purpose is to allow you to decrypt your password data under
one PBKDF and reencrypt that data using another key derivation function in case you want to migrate from one PBKDF to another.

# Optional features

Beginning with version 1.2.0 `rustpwman` is being built with support for the password cache implemented in [`pwman`](https://github.com/rmsk2/pwman). This feature can be
disabled by issuing the command `cargo build --release --no-default-features` on all supported platforms. When the feature is active `rustpwman` attempts to read the 
password for the data file specified by the `-i` option from the cache provided by `pwserv`.

If this does not succeed, the user is requested to enter a password as was the case in Version 1.1.0 and below. If on the other hand the password was successfully read, the 
user is asked to confirm that it should be used. Through the correspondig dialog the user is also able to clear the password from the cache. 

# Rustpwman under Windows

## Native

The good news is that it works and it even works well. I have tested the `pancurses` backend of `cursive` under Windows. The [`pancurses`](https://github.com/ihalila/pancurses) backend 
uses a binding to a C library and requires an [installed C compiler](https://github.com/ihalila/pdcurses-sys) in order to build. On the other hand Rust itself is dependent on a C 
compiler when used under Windows. When building `rustpwman` for Windows the `Cargo.toml` file has to be modified. The line `cursive = "0.20"` has to be removed or commencted out
and the following lines have to be appended to the file:

```
pancurses = "0.17.0"
pdcurses-sys = "0.7.1"

[dependencies.cursive]
version = "0.20"
default-features = false
features = ["pancurses-backend"]
```

In order to build `rustpwman` with the password cache feature you then have to use the command `cargo build --release --no-default-features --features pwmanclientwin`. You should
additionally build the `paste_utf8.exe` tool by running `build_paste_utf8.bat` in a Visual Studio developer prompt which enables you to paste the clipboard contents while editing
an entry. 

This batch file also builds `winfilter.exe` from the rust source `winfilter.rs`. This tool copies its stdin to stdout while filtering out the Escape sequence `ESC[?1002l` from its 
input (if it appears at the beginning of the stream). Therefore if you pipe the output of `rustpwman` through `winfilter.exe` you can cleanup `rustpwman`'s output in order to
make further processing easier.

I have tested `rustpwman` with the `pancurses` backend in the normal `cmd.exe` console and the new [Windows Terminal](https://www.microsoft.com/en-us/p/windows-terminal/9n0dx20hk701#activetab=pivot:overviewtab). Both work well.

## Windows Subsystem for Linux (WSL)

Version 1.0.0: As expected, building `rustpwman` for WSL works without problems after installing all dependencies like `git`, `gcc` and `libncurses`. The resulting application also works but there is a perceptible decrease in performance when compared to the native version which uses the `pancurses` backend.

Version 1.2.8 and higher: Building and running `rustpwman` works. Performance is still not quite on the same level as the native version (TUI flickers a bit when updating the screen) but overall performance 
has improved with respect to the previous test mentioned above.

# Caveats

This section provides information about stuff which is in my view suboptimal and should be (and possibly will be) improved in the future.

- At the moment I do not attempt to overwrite memory that holds sensitive information when `rustpwman` is closed. This may be a problem when `rustpwman` is used in an environment where an attacker can gain access to memory previously used by `rustpwman`, i.e. when sharing a machine with an attacker.
- When the list of entries changes (after an add or delete) it may be possible that the entry selected after the change is not visible in the `ScrollView` on the left. I was not successfull in forcing cursive to scroll to the newly selected entry. This is most probably my fault and meanwhile an appropriate warning dialog is displayed.
- I am fairly new to Rust. I guess it shows in the code.
- On a MacBook Air 2018 using the touchpad to click elements in the TUI does not work. The problem does not manifest itself when using a mouse. Using the touchpad seems to work though on other models. I do not think that this is a hardware problem on my MacBook and I unfortunately have no idea why this happens.
- On MacOS using the mouse scroll wheel or the Page Up/Down keys confuses cursive. This does not happen on Linux or Windows.
- On Windows a spurious Escape sequence `ESC[?1002l` is printed to stdout when the TUI application stops. This does not happen on Linux or MacOS. It happens less frequently when using the Windows terminal. By piping the output of `rustpwan` to `winfilter.exe` you can remove this unwanted data from the output.
- In non `--release` builds scrypt with the chosen parameters is *extremely* slow

