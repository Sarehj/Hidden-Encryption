# Hidden-Encryption

## Overview
This project focuses on understanding and applying cryptographic techniques to achieve hidden encryption and plausible deniability. Participants will gain practical experience with symmetric-key encryption, decryption, and cryptographic hashing. By working through tasks involving AES encryption algorithms, the project simulates real-world scenarios where secure data storage and protection against unauthorized access are crucial.

## Tasks:
#### Task 1: Extracting Encrypted Information
Extract and decrypt hidden information from a binary file using AES-128-ECB.

* Input: task1.data (binary data file) and task1.key (hexadecimal encryption key).
* Objective: Locate the encrypted blob within task1.data, decrypt it, and store the output in file1.data.

#### Task 2: Creating an Encrypted Data Blob
Create and embed an encrypted data blob within a container file using AES-128-ECB.

* Input: task2.data (binary data file), task2.key (numeric encryption key), and task2.offset (offset for embedding the blob).
* Objective: Create an encrypted blob from task2.data using the key and embed it within a container file padded to 2048 bytes. Store the output in file2.data.

#### Task 3: Program for Extracting Data (Hiddec)
Develop a program (Hiddec) to extract and decrypt data from a container file supporting both AES-128-ECB and AES-128-CTR.

###### Arguments:

--key=KEY: Hexadecimal encryption key.

--ctr=CTR: Initial counter value for AES-128-CTR mode.

--input=INPUT: Input container file.

--output=OUTPUT: Output file for decrypted data.

Example:

`
$ java Hiddec --key=92d4ab32eac2d8a0042342e0fdbe80f5 --input=container.data --output=plain.txt
`

#### Task 4: Program for Creating Data Blobs (Hidenc)
Create a program (Hidenc) to generate and embed an encrypted data blob within a container file, supporting AES-128-ECB and AES-128-CTR.

###### Arguments:

--key=KEY: Hexadecimal encryption key.

--ctr=CTR: Initial counter value for AES-128-CTR mode.

--offset=NUM: Offset for embedding the blob.

--input=INPUT: Input data file.

--output=OUTPUT: Output container file.

--template=TEMPLATE: Template file for the container.

--size=SIZE: Total size of the output file (in bytes).

Example:

`
$ java Hidenc --key=92d4ab32eac2d8a0042342e0fdbe80f5 --ctr=abcdef --offset=128 --input=task4.data --output=file4.data --size=2048
`
