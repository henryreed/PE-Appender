# -*- coding: utf-8 -*-
# Creative Commons Legal Code
#
# CC0 1.0 Universal
#
#     CREATIVE COMMONS CORPORATION IS NOT A LAW FIRM AND DOES NOT PROVIDE
#     LEGAL SERVICES. DISTRIBUTION OF THIS DOCUMENT DOES NOT CREATE AN
#     ATTORNEY-CLIENT RELATIONSHIP. CREATIVE COMMONS PROVIDES THIS
#     INFORMATION ON AN "AS-IS" BASIS. CREATIVE COMMONS MAKES NO WARRANTIES
#     REGARDING THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS
#     PROVIDED HEREUNDER, AND DISCLAIMS LIABILITY FOR DAMAGES RESULTING FROM
#     THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS PROVIDED
#     HEREUNDER.
#
# Statement of Purpose
#
# The laws of most jurisdictions throughout the world automatically confer
# exclusive Copyright and Related Rights (defined below) upon the creator
# and subsequent owner(s) (each and all, an "owner") of an original work of
# authorship and/or a database (each, a "Work").
#
# Certain owners wish to permanently relinquish those rights to a Work for
# the purpose of contributing to a commons of creative, cultural and
# scientific works ("Commons") that the public can reliably and without fear
# of later claims of infringement build upon, modify, incorporate in other
# works, reuse and redistribute as freely as possible in any form whatsoever
# and for any purposes, including without limitation commercial purposes.
# These owners may contribute to the Commons to promote the ideal of a free
# culture and the further production of creative, cultural and scientific
# works, or to gain reputation or greater distribution for their Work in
# part through the use and efforts of others.
#
# For these and/or other purposes and motivations, and without any
# expectation of additional consideration or compensation, the person
# associating CC0 with a Work (the "Affirmer"), to the extent that he or she
# is an owner of Copyright and Related Rights in the Work, voluntarily
# elects to apply CC0 to the Work and publicly distribute the Work under its
# terms, with knowledge of his or her Copyright and Related Rights in the
# Work and the meaning and intended legal effect of CC0 on those rights.
#
# 1. Copyright and Related Rights. A Work made available under CC0 may be
# protected by copyright and related or neighboring rights ("Copyright and
# Related Rights"). Copyright and Related Rights include, but are not
# limited to, the following:
#
#   i. the right to reproduce, adapt, distribute, perform, display,
#      communicate, and translate a Work;
#  ii. moral rights retained by the original author(s) and/or performer(s);
# iii. publicity and privacy rights pertaining to a person's image or
#      likeness depicted in a Work;
#  iv. rights protecting against unfair competition in regards to a Work,
#      subject to the limitations in paragraph 4(a), below;
#   v. rights protecting the extraction, dissemination, use and reuse of data
#      in a Work;
#  vi. database rights (such as those arising under Directive 96/9/EC of the
#      European Parliament and of the Council of 11 March 1996 on the legal
#      protection of databases, and under any national implementation
#      thereof, including any amended or successor version of such
#      directive); and
# vii. other similar, equivalent or corresponding rights throughout the
#      world based on applicable law or treaty, and any national
#      implementations thereof.
#
# 2. Waiver. To the greatest extent permitted by, but not in contravention
# of, applicable law, Affirmer hereby overtly, fully, permanently,
# irrevocably and unconditionally waives, abandons, and surrenders all of
# Affirmer's Copyright and Related Rights and associated claims and causes
# of action, whether now known or unknown (including existing as well as
# future claims and causes of action), in the Work (i) in all territories
# worldwide, (ii) for the maximum duration provided by applicable law or
# treaty (including future time extensions), (iii) in any current or future
# medium and for any number of copies, and (iv) for any purpose whatsoever,
# including without limitation commercial, advertising or promotional
# purposes (the "Waiver"). Affirmer makes the Waiver for the benefit of each
# member of the public at large and to the detriment of Affirmer's heirs and
# successors, fully intending that such Waiver shall not be subject to
# revocation, rescission, cancellation, termination, or any other legal or
# equitable action to disrupt the quiet enjoyment of the Work by the public
# as contemplated by Affirmer's express Statement of Purpose.
#
# 3. Public License Fallback. Should any part of the Waiver for any reason
# be judged legally invalid or ineffective under applicable law, then the
# Waiver shall be preserved to the maximum extent permitted taking into
# account Affirmer's express Statement of Purpose. In addition, to the
# extent the Waiver is so judged Affirmer hereby grants to each affected
# person a royalty-free, non transferable, non sublicensable, non exclusive,
# irrevocable and unconditional license to exercise Affirmer's Copyright and
# Related Rights in the Work (i) in all territories worldwide, (ii) for the
# maximum duration provided by applicable law or treaty (including future
# time extensions), (iii) in any current or future medium and for any number
# of copies, and (iv) for any purpose whatsoever, including without
# limitation commercial, advertising or promotional purposes (the
# "License"). The License shall be deemed effective as of the date CC0 was
# applied by Affirmer to the Work. Should any part of the License for any
# reason be judged legally invalid or ineffective under applicable law, such
# partial invalidity or ineffectiveness shall not invalidate the remainder
# of the License, and in such case Affirmer hereby affirms that he or she
# will not (i) exercise any of his or her remaining Copyright and Related
# Rights in the Work or (ii) assert any associated claims and causes of
# action with respect to the Work, in either case contrary to Affirmer's
# express Statement of Purpose.
#
# 4. Limitations and Disclaimers.
#
#  a. No trademark or patent rights held by Affirmer are waived, abandoned,
#     surrendered, licensed or otherwise affected by this document.
#  b. Affirmer offers the Work as-is and makes no representations or
#     warranties of any kind concerning the Work, express, implied,
#     statutory or otherwise, including without limitation warranties of
#     title, merchantability, fitness for a particular purpose, non
#     infringement, or the absence of latent or other defects, accuracy, or
#     the present or absence of errors, whether or not discoverable, all to
#     the greatest extent permissible under applicable law.
#  c. Affirmer disclaims responsibility for clearing rights of other persons
#     that may apply to the Work or any use thereof, including without
#     limitation any person's Copyright and Related Rights in the Work.
#     Further, Affirmer disclaims responsibility for obtaining any necessary
#     consents, permissions or other rights required for any use of the
#     Work.
#  d. Affirmer understands and acknowledges that Creative Commons is not a
#     party to this document and has no duty or obligation with respect to
#     this CC0 or use of the Work.
#
# For more information, please see
# <http://creativecommons.org/publicdomain/zero/1.0/>

import argparse
import os
import re
import shutil
import struct
import sys


class ExeAppender:
    class Offset(int):
        def __new__(cls, value, length):
            obj = int.__new__(cls, value)
            obj.length = length
            return obj

        def __len__(self):
            return self.length

    class PEConstants:
        def __setattr__(self, attr, value):
            if hasattr(self, attr):
                raise Exception("Attempting to alter read-only value")

            self.__dict__[attr] = value

        def __init__(self):
            self.padding_size = 8
            self.PE_header: bytes = b'PE\0\0'
            self.MS_DOS_header_offset = ExeAppender.Offset(60, 4)  # 0x3C, MS DOS header field e_lfanew; discloses
            #                                                        PE header offset
            self.optional_header_size_offset = ExeAppender.Offset(20, 2)  # mSizeOfOptionalHeader;
            #                                                                offset is from the start of the PE_header
            self.optional_header_offset = 24
            self.checksum_offset = 64  # Offset starting from the beginning of the optional header;
            #                             same offset for 32- and 64-bit
            self.optional_header_magic_64: bytes = b'\x0b\x02'  # mMagic indicating the binary is a PE32+ file (64 bit)
            self.optional_header_magic_32: bytes = b'\x0b\x01'  # mMagic indicating the binary is a PE32 file (32 bit)
            # Offsets starting from the beginning of the optional header
            self.certificate_table_offset_offset_32 = ExeAppender.Offset(128, 4)
            self.certificate_table_offset_offset_64 = ExeAppender.Offset(144, 4)
            self.certificate_table_size_offset_32 = ExeAppender.Offset(132, 4)
            self.certificate_table_size_offset_64 = ExeAppender.Offset(148, 4)

    class PEVariables:
        def __init__(self):
            self.PE_header_offset = -1
            self.certificate_table_offset = -1
            self.certificate_table_size = -1
            self.certificate_table_size_offset = -1

        def __str__(self):
            return str(vars(self))

        def __bool__(self):
            """Returns false if any variable is negative, otherwise returns true"""
            for value in vars(self).values():
                if value < 0:
                    return False
            return True

    @staticmethod
    def generate_checksum(binary: bytes, absolute_checksum_offset: int) -> bytes:
        """Generates a checksum using the Microsoft PE checksum algorithm given a binary

        :param absolute_checksum_offset: Checksum offset relative to the beginning of the file
        :param binary: Bytes object of the binary
        :return: Bytes object representing the checksum
        """
        checksum: int = 0

        # Get rid of the checksum field
        binary_no_checksum = binary[:absolute_checksum_offset] + binary[absolute_checksum_offset + 4:]
        # Add padding
        if len(binary_no_checksum) % 4 != 0:
            num_null: int = 4 - len(binary_no_checksum) % 4
            binary_no_checksum: bytes = binary_no_checksum + (b'\x00' * num_null)

        chunks = re.findall(b'....', binary_no_checksum, flags=re.S)
        for chunk in chunks:
            checksum += struct.unpack('I', chunk)[0]

        while checksum > 2 ** 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)

        # Length of the original binary is needed here, rather than the checksumless, padded length.
        return struct.pack('I', checksum + len(binary))

    @staticmethod
    def pad_payload(payload: bytes, padding_size: int = 8) -> bytes:
        """Returns a padded payload (without padding digital signature breaks)"""
        padding_len = padding_size - (len(payload) % padding_size)
        return payload + (b'\0' * padding_len)  # Padding must use null bytes

    def reader(self, file_location: str):
        variable = ExeAppender.PEVariables()
        constant = ExeAppender.PEConstants()
        with open(file_location, 'rb') as file:
            file.seek(constant.MS_DOS_header_offset)
            variable.PE_header_offset = struct.unpack('<I', file.read(len(constant.MS_DOS_header_offset)))[0]

            file.seek(variable.PE_header_offset)
            if file.read(len(constant.PE_header)) != constant.PE_header:
                raise ValueError("e_lfanew is not pointing at a valid PE header")

            file.seek(variable.PE_header_offset + constant.optional_header_offset)
            optional_header_magic = file.read(len(constant.optional_header_magic_32))  # Optional header magic length is
            #                                                                           the same for both 32- and 64-bit

            if optional_header_magic == constant.optional_header_magic_32:
                certificate_table_offset_offset = constant.certificate_table_offset_offset_32
                variable.certificate_table_size_offset = constant.certificate_table_size_offset_32
            elif optional_header_magic == constant.optional_header_magic_64:
                certificate_table_offset_offset = constant.certificate_table_offset_offset_64
                variable.certificate_table_size_offset = constant.certificate_table_size_offset_64
            else:
                raise ValueError("Invalid optional header magic")

            # Get the offset for certificates stored towards the end of the file
            file.seek(variable.PE_header_offset + constant.optional_header_offset + certificate_table_offset_offset)
            variable.certificate_table_offset = struct.unpack('<I', file.read(
                len(variable.certificate_table_size_offset)))[0]
            #                                                            Length for 32 and 64 bit is the same

            # Get the first certificate table size stored inside the optional header
            file.seek(variable.PE_header_offset + constant.optional_header_offset
                      + variable.certificate_table_size_offset)
            certificate_table_size = struct.unpack('<I', file.read(len(variable.certificate_table_size_offset)))[0]

            # Get the certificate table size stored alongside the actual certificate table
            file.seek(variable.certificate_table_offset)
            certificate_table_size_2 = struct.unpack('<I', file.read(len(variable.certificate_table_size_offset)))[0]

            if certificate_table_size_2 != certificate_table_size:
                raise ValueError("The file is corrupt: certificate table sizes do not match. First table: "
                                 + str(certificate_table_size) + ", second table: " + str(certificate_table_size_2))
            else:
                variable.certificate_table_size = certificate_table_size

        if variable:
            return variable
        else:
            raise ValueError("Unable to assign a variable. All variables: " + str(variable))

    def appender(self, file_location: str, payload_location: str, variable):
        constant = ExeAppender.PEConstants()
        with open(file_location, 'r+b') as file:
            with open(payload_location, 'rb') as payload_reader:
                unpadded_payload = payload_reader.read()
            # Add the size of our new addition at the end in 4 bytes s.t. len(executable) - 4 - len(payload)
            # would get us the offset to the start of the payload.
            # Some notes:
            # * Using big-endian b/c the padding MUST be null bytes, and it's easier to differentiate this way
            #    * E.g., given payload b'payload', we would append b'payload\x00\x00\x00\x07'. If we pad this, it would
            #      be b'payload\x00\x00\x00\x07\x00\x00\x00\x00\x00'
            #    * To get to our arbitrary payload, we read backwards until we reach a character that is not a null
            #    byte. From there, we can read 4 more bytes to get the length of the payload, then read back the length
            #    of that payload.
            # * Maximum size of our payload in bytes is 256**4 - len(digital_cert) - 4, ~4.29GB
            unpadded_payload_w_size = unpadded_payload + struct.pack('>I', os.path.getsize(payload_location))
            padded_payload = self.pad_payload(unpadded_payload_w_size, constant.padding_size)

            new_certificate_table_size = struct.pack('<I', variable.certificate_table_size
                                                     + len(padded_payload))

            file.seek(variable.PE_header_offset
                      + constant.optional_header_offset
                      + variable.certificate_table_size_offset)
            file.write(new_certificate_table_size)

            file.seek(variable.certificate_table_offset)
            file.write(new_certificate_table_size)

            file.seek(os.path.getsize(file_location))
            file.write(padded_payload)

            file.seek(0)
            checksum = ExeAppender.generate_checksum(file.read(), variable.PE_header_offset
                                                     + constant.optional_header_offset + constant.checksum_offset)

            file.seek(variable.PE_header_offset + constant.optional_header_offset + constant.checksum_offset)
            file.write(checksum)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Appends arbitrary data to the end of an executable while maintaining '
                                                 'a valid digital signature')
    parser.add_argument('original', metavar='[executable location]', type=str, nargs=1,
                        help='File location of the executable to which you wish to append arbitrary data')
    parser.add_argument('payload', metavar='[payload location]', type=str, nargs=1,
                        help='File location of the arbitrary data to append to the executable')
    parser.add_argument('final', metavar='[new executable location]', type=str, nargs='?',
                        help='File location of where the new executable should be. If this value is not supplied, the '
                             'original executable will be modified, instead.')

    args = parser.parse_args()

    # Check that arguments point to valid files
    for unverified_file in [args.original, args.payload]:
        if not os.path.isfile(unverified_file[0]):
            print("Cannot read the file at this location: " + unverified_file[0], file=sys.stderr)
            sys.exit(1)

    if args.final is None:
        args.final = args.original[0]
    else:
        shutil.copy2(args.original[0], args.final)

    appender = ExeAppender()
    variables = appender.reader(args.original[0])
    appender.appender(args.final, args.payload[0], variables)
