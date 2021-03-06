# rustpwman

A simple password manager written in Rust using the [cursive TUI library](https://github.com/gyscos/cursive). **This is work in progress**.

The password manager offers the following functionality:

```
rustpwman 0.9.0
Martin Grap <rmsk2@gmx.de>
A password manager for the cursive TUI in Rust

USAGE:
    rustpwman [SUBCOMMAND]

FLAGS:
    -h, --help       
            Prints help information

    -V, --version    
            Prints version information


SUBCOMMANDS:
    cfg     Change configuration
    dec     Decrypt file
    enc     Encrypt file
    gui     Open file in TUI
    help    Prints this message or the help of the given subcommand(s)
```

The `enc` and `dec` commands can be used to reencrypt an existing data file when one wishes to switch to another password based key derivation function.

You may wonder why someone writes a TUI application in 2021. The main reason is portability without creating a dependency to any of the usual GUI toolkits. `rustpwman` should work on MacOS, Linux and Windows and it should compile without the necessity to install more or less exotic toolchains.

# Introduction

The basic concept of `rustpwman` is to manage a set of entries which have a value or content. The entries are presented in a flat list and no further structuring is offered at the moment. In order to start the programm use

```
rustpwman gui -i <file_name>
```

or `cargo run --release -- gui -i <file_name>` which will result, after a successful password entry, in a window similar to this one.  

![](/screenshot.png?raw=true "Screenshot of rustpwman")

If the file specified through the `-i` parameter does not exist `rustpwman` will create a new data file using that name 
after you have supplied a suitable password.

## About the crypto

It is expected that the referenced file contains encrypted password information. `rustpwman` encrypts its data at rest using AES-256 in GCM mode with a 128 bit tag length and a 96 bit nonce. The encrypted data file is a simple JSON data structure. This may serve as an example:

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

If the referenced file does not exist the user is offered to create an empty encrypted data file using a new password and the file name specified on the command line. As a default the actual encryption key is derived from the specified password using the following calculation:

```
SHA-256( password | salt | password )
```

where `salt` is a random value of appropriate length and `|` symbolizes concatenation. It is also possible to select this or another password based key derivation function through the `--kdf` option or by a [config file](#configuration). Currently `scrypt`, `argon2` and `sha256` are valid as a parameter for this option and as a config file entry.

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

# Functionality

## The File menu
The `File` menu contains the following entries.

### Save file

Selecting this entry saves the encrypted data file using the password that was specified during program start or has been changed using `Change password`.

### Change password

Using this entry allows to select a new password. After a new password has been selected the encrypted data file is saved automatically. The new password is also used in subsequent save operations.

### About

Shows an about dialog containing information about the author and the program version.

### Quit and print

Selecting this entry ends the program and prints the value of the currently selected entry to the CLI window after
the TUI has been closed. About the reasoning behind this idea have a look at the section [A note about the lack of the clipboard](#a-note-about-the-lack-of-the-clipboard). 

### Quit

Through this menu entry the program can be closed. Before ending the program it is checked if there are unsaved changes. If there are then the user is warned correspondingly and has the possibility to not end the program in order to save the
changed state. 

## The Entry menu

This menu contains all operations that are supported with respect to entries.

### Edit entry

This menu entry allows to manually edit the value or contents of the currently selected password entry. 

### Add entry

Select this menu entry to create a new empty password entry. Use then `Edit entry`, `Load entry` or `Generate password` to add information to the newly created password entry.

### Delete entry 

Use this menu entry to delete the currently selected password entry. Before deleting the entry the user is prompted whether the entry is really to be deleted. 

### Rename entry 

Via this menu entry the currently selected entry can be renamed. It is not allowed to use the empty string as a new name. rustpwman also checks that no entry having the new name already exists.

### Clear entry

Via this menu entry the contents of the currently selected password entry can be cleared. As with deletion the user is prompted for confirmation before the contents is cleared.

### Load entry

This allows to load the contents of a (text-)file into an entry. The current contents is overwritten without further notice to the user.

### Generate password

This menu entry allows to append a randomly generated password to the currently selected entry. The user has to choose the
parameters to use while generating the password. One parameter is the security level in bits (of entropy). This describes how large the set of passwords should be from which the generator selects one at random. A security level of `k` bits means that there are `2**k` passwords to choose from. This parameter in essence determines the difficulty for an attacker when performing a brute force password search. The default
security level is 80 bits but this can be changed by a config file (see below).

Additionally the user may select the set of characters which may appear in the randomly generated password. Currently the following alternatives are offered:

- Base64, where the potential padding character `=` is removed
- Hex
- Special: This password generator aims to create pronouncable passwords which are constructed from the following elements: A sequence of two letter groups which consist of a consonant followed by a vowel. There are 420 such groups. Therefore when selecting one of these groups at random each one contains 8.7 bits of entropy. The final four character group is a consonant followed by a three digit number. There are 26*1000 such four character groups so it has an entropy of 14.6 Bits when one is chosen randomly.

According to the Rust documentation the random number generator underlying the whole process is a *thread-local CSPRNG with periodic seeding from OsRng. Because this is local, it is typically much faster than OsRng. It should be secure, though the paranoid may prefer OsRng*.

# A note about the lack of the clipboard

While using cursive was a largely pleasant experience it has to be noted that copying and pasting text is not possible in a terminal window while the cursive application is running. This in turn is probably an unfixable problem as cursive by definition controls the cursor in the terminal window, which may preclude the OS from "doing its thing". 

While a password manager is still useful without copy and paste it is not optimal to first read and then type randomly chosen passwords into password dialogs that also hide what is typed. I therefore came up with the solution `Quit and print`. When using this menu item `rustpwman` is stopped and the contents of the currently selected entry is printed to the terminal window after the TUI has been closed and control of the OS over the terminal has been restored. In other words the necessary information can now be copied from the terminal into the clipboard and pasted where needed.

A similar problem occurs when importing existing password information into `rustpwman`. Ideally it would be possible to select the information in the other application and paste it into the terminal in which `rustpwman` is running. As a workaround there is a possibility to load data from a file into an existing entry using the `Load entry` menu entry.

# Configuration

Rustpwman uses a TOML config file for setting the default security level, the default password generator and the default PBKDF. 

```
[defaults]
seclevel = 18
pbkdf = "argon2"
pwgen = "special"
```

- `seclevel` has to be an integer between 0 and 23. The security level in bits is calculated as (`seclevel` + 1) * 8. 
- `pbkdf` is a string that can assume the values `scrypt`, `argon2`, `sha256`
- `pwgen` is one of the strings `base64`, `hex` or `special`

The config file is stored in the users' home directory in a file named `.rustpwman`. To change these defaults either edit the config
file by hand or use `rustpwman cfg` which will open a window similar to this one

![](/scrshot_cfg.png?raw=true "Screenshot of rustpwman cfg")

# Rustpwman under Windows

## Native

The good news is that it works and it even works well. I have tested the `crossterm` and the `pancurses` backend of `cursive` under Windows. The [`crossterm`](https://github.com/crossterm-rs/crossterm) backend is pure Rust but the resulting program runs so slow that it is borderline unusable. The [`pancurses`](https://github.com/ihalila/pancurses) backend is a binding to a C library and requires an [installed C compiler](https://github.com/ihalila/pdcurses-sys) in order to build. When building `rustpwman` for Windows the `Cargo.toml` file has to be modified. The line `cursive = "0.16.3"` has to be removed and the following lines have to be appended to the file:

```
pancurses = "0.16.1"
pdcurses-sys = "0.7.1"

[dependencies.cursive]
version = "0.16.3"
default-features = false
features = ["pancurses-backend"]
```

I have tested `rustpwman` with the `pancurses` backend in the normal `cmd.exe` console and the new [Windows Terminal](https://www.microsoft.com/en-us/p/windows-terminal/9n0dx20hk701#activetab=pivot:overviewtab). Both work well and the only oddity is the fact that when closing the TUI in a `cmd.exe` an escape sequence `[?1002l` is printed. This does not happen when using the Windows Terminal.

## Windows Subsystem for Linux (WSL)

As expected, building `rustpwman` for WSL works without problems after installing all dependencies like `git`, `gcc` and `libncurses5`. The resulting application also works but there is a perceptible decrease in performance when compared to the native version which uses the `pancurses` backend.  

# Caveats

This section provides information about stuff which is in my view suboptimal and should be (and possibly will be) improved in the future.

- Beginning with version 0.8 the name of the key derivation function is stored in the encrypted data file and checked upon decryption. You may have to manually add the line `"PbKdf": "sha256",` (or similar if an alternative PBKDF was used) to existing JSON files.
- At the moment I do not attempt to overwrite memory that holds sensitive information when `rustpwman` is closed. This may be a problem when `rustpwman` is used in an environment where an attacker can gain access to memory previously used by `rustpwman`, i.e. when sharing a machine with an attacker.
- When the list of entries changes (after an add or delete) it may be possible that the entry selected after the change is not visible in the `ScrollView` on the left. I was not successfull in forcing cursive to scroll to the newly selected entry. This is most probably my fault and meanwhile an appropriate warning dialog is displayed.
- I am fairly new to Rust. I guess it shows in the code.
- On a MacBook Air 2018 using the touchpad to click elements in the TUI does not work. The problem does not manifest itself when using a mouse. Using the touchpad seems to work though on other models. I do not think that this is a hardware problem on my MacBook and I unfortunately have no idea why this happens.
- In non `--release` builds scrypt with the chosen parameters is *extremely* slow
- Source for PBKDF parameter choices https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Removed `bcrypt` due to a lack of testability. After looking at the crate `bcrypt-pbkdf`, which I originally used, I came to the conclusion that this crate does not implement the 
"real" `bcrypt`. It only provides a variant of the original. See https://flak.tedunangst.com/post/bcrypt-pbkdf.

