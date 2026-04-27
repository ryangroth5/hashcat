Extract a hashcat mode 33200 hash from a gocryptfs.conf file:

    python3 gocryptfs2hashcat.py /path/to/gocryptfs.conf > out.hash
    hashcat -m 33200 out.hash wordlist.txt

Requires gocryptfs >= v1.3 with the "HKDF" entry present in the FeatureFlags
array of gocryptfs.conf. This covers all filesystems created since gocryptfs
v1.3 (2018-04-01) and is the default for all current gocryptfs installations.

The example.hash file was generated from a real gocryptfs 2.4.0 volume
(password: password123).
