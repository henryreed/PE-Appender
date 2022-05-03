# PE Appender

Appends arbitrary data to a PE file without breaking the digital signature of the file. 

Implemented in Python 3.

## Features
* Supports both 32- and 64-bit PEs (PE32 and PE32+)
* Runs on Windows, macOS and Linux
* Uses a more efficient algorithm for checksum generation. (This has zero real-world impact, but it is cool!)
* Does not use external libraries to parse or modify PE headers

## Demo

![Demo GIF](pe_appender_demo.gif)

## Usage

```commandline
usage: pe-appender.py [-h]
                      [executable location] [payload location]
                      [[new executable location]]

Appends arbitrary data to the end of an executable while maintaining a valid
digital signature

positional arguments:
  [executable location]
                        File location of the executable to which you wish to
                        append arbitrary data
  [payload location]    File location of the arbitrary data to append to the
                        executable
  [new executable location]
                        File location of where the new executable should be.
                        If this value is not supplied, the original executable
                        will be modified, instead.

options:
  -h, --help            show this help message and exit
```

A bundled exe can also be used, see the dist directory or the releases section. The bundled executable was created using
PyInstaller version 5.0.1 and Python 3.10.4.

## What does an appended payload look like?

Given the following payload:
```python
b'Henry Reed is a handsome demigod who writes perfect code'
```

We calculate that payload's length and insert it as an unsigned, big-endian integer, changing the payload into:

```python
b'Henry Reed is a handsome demigod who writes perfect code\x00\x00\x00\x38'
```

To get our payload, we read the last four bytes of the file, and use that to determine the length of our payload. Then, 
our offset from the beginning of the file to the payload would be:

```
offset = len(executable) - len(payload) - 4
```

## Related Projects

### References

* _Changing a Signed Executable without Altering Windows Digital Signatures_ by A. Barthe,
[Link](https://blog.barthe.ph/2009/02/22/change-signed-executable/)
* _An Analysis of the Windows PE Checksum Algorithm_ by J. Walton,
[Link](https://www.codeproject.com/Articles/19326/An-Analysis-of-the-Windows-PE-Checksum-Algorithm)
* "Can anyone define the Windows PE Checksum Algorithm?" on Stack Overflow, 
[Link](https://stackoverflow.com/questions/6429779/can-anyone-define-the-windows-pe-checksum-algorithm/10584253#10584253)
* pefile Python Library by E. Carrera, [Link](https://github.com/erocarrera/pefile)

### Software That Does the Same Thing

| Language   | Architectures | License                                              | Author              | Repository Link                                                                                |
|------------|---------------|------------------------------------------------------|---------------------|------------------------------------------------------------------------------------------------|
| C++        | 32-bit only   | All rights reserved (license unset)                  | A. Barthe, J. Klein | [GitHub](https://github.com/jason-klein/signed-nsis-exe-append-payload)                        |
| JavaScript | 32-bit only   | MIT License                                          | R. Timmermans       | [GitHub](https://github.com/rolftimmermans/node-exe-append)                                    | 
| Ruby       | 32-bit only   | MIT License, Creative Commons Attribution-ShareAlike | B. Wamboldt         | [GitHub](https://github.com/brandonwamboldt/ruby-exe-appender/blob/master/lib/exe_appender.rb) |