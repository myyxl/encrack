# encrack
encrack was made to highlight vulnerabilities and bad code practices present in the Externer-Noten-Client (ENC). The ENC is used to edit grades and other student information obtained from the Lehrer- und Schülerdatenbank (LUSD), the central database containing student information in Hesse.

When a teacher wants to edit information about a student, they have to download an archive containing the lastest ENC and the student information in an encrypted xml file. After starting the ENC, they have to select the path to the encrypted xml file and provide a password to decrypt the file. This password is shown after downloading the archive from the website. encrack can crack these encrypted files without knowing the password.

Cracking these files is possible because of a self-made and unsecure key derivation function.
