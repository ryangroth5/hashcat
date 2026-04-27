#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##
## gocryptfs (v1.3+, HKDF-enabled) master-key cracking
##
## Hash format:
##   $gocryptfs$N$r$p$<base64_salt>$<base64_encrypted_key>
##
## EncryptedKey is nonce(16) || ciphertext(32) || tag(16) = 64 bytes total.
##
## Crypto chain:
##   password + salt --scrypt(N,r=8,p=1)--> KEK (32 bytes)
##   KEK -----------HKDF-Extract(key=0x00*32)-> PRK
##   PRK -----------HKDF-Expand(info="AES-GCM file content encryption\x01")--> enc_key
##   enc_key + nonce + MasterKey --AES-256-GCM--> ciphertext + tag
##
## Only covers gocryptfs >= v1.3 with the "HKDF" FeatureFlag present in
## gocryptfs.conf.  Earlier versions (v1.2 and older) used the raw scrypt
## output as the AES-GCM key with no HKDF step and a 12-byte nonce (60-byte
## EncryptedKey) -- that variant is NOT handled by this mode.
##

use strict;
use warnings;

use Crypt::ScryptKDF    qw (scrypt_raw);
use Crypt::AuthEnc::GCM qw ();
use Digest::SHA         qw (hmac_sha256);
use MIME::Base64        qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

# ---- HKDF (RFC 5869) via HMAC-SHA256 ----------------------------------------

sub hkdf_extract
{
  my ($salt, $ikm) = @_;
  return hmac_sha256 ($ikm, $salt);
}

sub hkdf_expand
{
  my ($prk, $info, $len) = @_;

  my $t    = '';
  my $okm  = '';
  my $ctr  = 1;

  while (length ($okm) < $len)
  {
    $t    = hmac_sha256 ($t . $info . chr ($ctr), $prk);
    $okm .= $t;
    $ctr++;
  }

  return substr ($okm, 0, $len);
}

# ---- core hash generation ---------------------------------------------------

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift // random_bytes (32);   # raw bytes
  my $nonce = shift // random_bytes (16);   # raw bytes
  my $mkey  = shift // random_bytes (32);   # MasterKey, raw bytes

  my $N = 65536;
  my $r = 8;
  my $p = 1;

  # Step 1: scrypt
  my $kek = scrypt_raw ($word, $salt, $N, $r, $p, 32);

  # Step 2: HKDF-Extract  (key = 0x00 * 32, data = kek)
  my $extract_salt = "\x00" x 32;
  my $prk          = hkdf_extract ($extract_salt, $kek);

  # Step 3: HKDF-Expand  (info = "AES-GCM file content encryption"; hkdf_expand appends counter)
  my $info    = "AES-GCM file content encryption";
  my $enc_key = hkdf_expand ($prk, $info, 32);

  # Step 4: AES-256-GCM  (AAD = 8 zero bytes = blockNo:0 + fileID:nil)
  my $aad = "\x00" x 8;
  my $aes = Crypt::AuthEnc::GCM->new ("AES", $enc_key, $nonce);
  $aes->adata_add ($aad);
  my $ct  = $aes->encrypt_add ($mkey);
  my $tag = $aes->encrypt_done ();

  # Encode
  my $salt_b64 = encode_base64 ($salt, "");
  my $ek_b64   = encode_base64 ($nonce . $ct . $tag, "");

  # Strip trailing '='
  $salt_b64 =~ s/=+$//;
  $ek_b64   =~ s/=+$//;

  return sprintf ('$gocryptfs$%u$%u$%u$%s$%s', $N, $r, $p, $salt_b64, $ek_b64);
}

# ---- verification -----------------------------------------------------------

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 11) eq '$gocryptfs$';

  my (undef, $sig, $N, $r, $p, $salt_b64, $ek_b64) = split /\$/, $hash;

  return unless defined $ek_b64;
  return unless $sig eq 'gocryptfs';
  return unless $N == 65536 && $r == 8 && $p == 1;

  my $salt  = decode_base64 ($salt_b64);
  my $ek    = decode_base64 ($ek_b64);

  return unless length ($salt) == 32;
  return unless length ($ek)   == 64;

  my $nonce = substr ($ek,  0, 16);
  my $ct    = substr ($ek, 16, 32);
  my $tag   = substr ($ek, 48, 16);

  my $word_packed = pack_if_HEX_notation ($word);

  # Derive enc_key the same way as generate_hash
  my $kek          = scrypt_raw ($word_packed, $salt, $N, $r, $p, 32);
  my $extract_salt = "\x00" x 32;
  my $prk          = hkdf_extract ($extract_salt, $kek);
  my $info         = "AES-GCM file content encryption";
  my $enc_key      = hkdf_expand ($prk, $info, 32);

  my $aad = "\x00" x 8;
  my $aes = Crypt::AuthEnc::GCM->new ("AES", $enc_key, $nonce);
  $aes->adata_add ($aad);
  my $pt = $aes->decrypt_add ($ct);

  my $ok = $aes->decrypt_done ($tag);

  return unless $ok == 1;

  my $new_hash = module_generate_hash ($word_packed, $salt, $nonce, $pt);

  return ($new_hash, $word);
}

1;
