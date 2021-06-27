# rustpwman

A simple password manager written in Rust using the cursive TUI library. In order to start the programm use

```
 ./rustpwman <file_name>
```

It is expected that the referenced file contains encrypted password information. `rustpwman` encrypts its
data using AES-256 in GCM mode with a 128 bit tag length and 96 bit nonce. The encrypted data file is a simple
JSON data structure. This may serve as an example:

```
{
  "Salt": "/qcBaihI/4wV1A==",
  "Nonce": "t8RCYaLY3Bsisl5K",
  "Data": "4YM5XNvMou3TukBnYCRCMoAhia2jaoBfyRIr+aGJ0dTrZTtiah4dm6W8gKnmt95/mDPBx2E+5Hy8cxzef4vOM0vTjy/2H9EFgpO5m7onxJTzBOgjqtnE4lH6vLiYJ+FN6GW+68Y1X7OgifCln8nP4D++u4vJnZEYgiAMB7YrjdvP7Evp4fHcx6/B/LM1ga7Cg4T57/a8SG7wK7hlBY+CUoVH9HKjzEZAMPyuyai/ZQMjgG1w9Bpn5zNnjntTn/K+y0hX209VTiEPK43DO/3d05tPrJfmkJNUsjskTn2teANooIlo9ZG1YMCNxe/r0ns8YPJEAlgS2R5HSNBodqgIiFcqQ9mSuta4iwaBG+DAZ5KHmVooLZ+L0djsgKtbEGVjjIVsaO/qFZpx"
}
 ```

If the referenced file does not exist the user is offered to create an empty encrypted data file using a new password using the file name specified on the command line.

The basic concept of `rustpwman` is to manage a set of entries which have corresponding values. The entries are presented in a flat list
and no further structuring is offered at the moment.

# Functionality

## The File menu
The `File` menu contains the following entries:

### Save file

Selecting this entry saves the encrypted data file using the password that what specified during program start.

### Change password

Using this entry allows to select a new password. After a new password has been selected the encrypted data file is saved
automatically.

### About

Shows an about dialog containing information about the author and the program version.

### Quit and print

Selecting this entry ends the program and prints the value of the currently selected entry to the CLI window after
the TUI has been closed. About the reasoning behind this idea have a look at the section `A note about the lack of the clipboard`. 

### Quit

Through this menu entry the program can be closed. Before ending the program it is checked if there are unsaved changes.
If there are then the user is warned correspondingly and has the possibility to not end the program in order to save the
changed state. 

## The Entry menu

This menu contains all operations that are supported with respect to entries.

### Edit entry

### Add entry

### Delete entry 

### Clear entry

### Load entry

### Generate password

# A note about the lack of the clipboard

# Caveats
