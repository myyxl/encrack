# encrack
encrack was made to highlight vulnerabilities and bad code practices present in the Externer-Noten-Client (ENC). The ENC is used to edit grades and other student information obtained from the Lehrer- und Schülerdatenbank (LUSD), the central database containing student information in Hesse.

When a teacher wants to edit information about a student, they have to download an archive containing the lastest ENC and the student information in an encrypted xml file. After starting the ENC, they have to select the path to the encrypted xml file and provide a password to decrypt the file. This password is shown after downloading the archive from the website. encrack can crack these encrypted files without knowing the password.

Cracking these files is possible because of a self-made and unsecure key derivation function.

## Externer-Noten-Client
### Decryption
The decryption process in the ENC from 2018 is the following:
```
+------------------+          +------------+         +---------+        +------------+
|                  |          |            |         |         |        |            |
| Entered password +--------->| CustomKDF  +-------->| PBKDF1  +------->| Decryption |
|                  |          |            |         |         |        |            |
+------------------+          +------------+         +---------+        +------------+
```
The entered password goes through a custom key derivation function and is then supplied to PBKDF1. This 32 byte key is then used to decrypt the file.
The decryption process of the 2018 version has two major flaws. The first one being, using PBKDF1 with only 2 iterations. And the second one, implementing an insecure custom derivation function, which will be covered in more detail later.

Something to note here, the reason the iterations were set to 2, is the fact that the code was simply copied:
https://www.codeproject.com/Tips/80688/Simple-Encryption-in-C

The code example linked, is also wrong. It uses SHA-1 as the hash algorithm but is requesting 32 bytes. Which is not possible in any other implementation besides Microsoft's .NET. SHA-1 produces a 20 byte long hash.


The latest obtained ENC version from 2021 uses the same process as before, with the difference that it uses PBKDF2 instead of PBKDF1. It also fixes one of the major flaws. It uses 400k iterations instead of 2. Even though this is an improvement, attacks are still possible through rainbow tables. Which take only around a day to generate. And the second major flaw still exists, the custom derivation function.

### Custom Derivation Function
The only reason the file cracking works is because of the custom derivation function. It works as follows:

The password used for encryption and which is shown on the website is always 8 characters long. It's a mix made of numbers, upper and lowercase letters and special characters. Once this password is supplied to the custom derivation function it goes through multiple bit shifting and character replacement operations. Most important is the end result. The function returns two strings and one of them is passed into PBKDF1/2. The returned string has always the same structure:

- 8 characters long
- Numbers from 0 - 7

Example: dk_DSm5G -> 43743557

With these information we can calculate the amount of possible keys: 8^8 = 16.777.216

### Cracking
Cracking is straightforward. Loop through all possibilites and check if the decryption was successful.

The cracking process can be optimized in the following ways. Besides multithreading and writing the cracker in a fast language like C or Rust, the decryption process itself, which has to be done 8^8 times, can be optimized. The encryption used by the ENC is AES CBC which allows us to only decrypt the first block of the encrypted blob. This results in a good speed improvement since the encrypted blob is quite big with multiple Mb's. Which slows down the decryption, because the whole blob would need to be decrypted otherwise. It's enough to only decrypted the first few bytes and check if it was successful. If not, next key. If yes, decrypt the whole blob.

The same principle can be applied to the version of 2021. The major difference here is that a rainbow table has to be generated first. Generating the keys with 400k iterations each cannot be done on the fly (Or would not make sense atleast). Instead a rainbow table is generated, with all 8^8 possible keys and each 400k iterations. Generation takes around 1 day, or less (depending on the threads and CPU). Once generated all thats left to do is go through the list and test each one by one. With multithreading this takes only a few seconds. 
