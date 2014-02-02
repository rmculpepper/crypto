#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>

/* Print error, don't abort */
void check_err(char *prefix) {
  long code = ERR_get_error();
  if (code)
    fprintf(stderr, "%s %s [%s, %s]\n", 
            prefix,
            ERR_reason_error_string(code),
            ERR_lib_error_string(code),
            ERR_func_error_string(code));
}

/* Print error and abort program */
void *err(char *msg) {
  fprintf(stderr, "%s\n", msg);
  check_err("");
  exit(1);
  return NULL;
}

EVP_PKEY *make_params(int curve_nid) {
  EVP_PKEY_CTX *paramsctx = NULL;
  EVP_PKEY *params = NULL;
  paramsctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (paramsctx == NULL) 
    return err("failed to make params ctx");
  if (1 != EVP_PKEY_paramgen_init(paramsctx)) 
    return err("failed to init params ctx");
  if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramsctx, curve_nid)) 
    return err("failed to set curve");
  if (!EVP_PKEY_paramgen(paramsctx, &params))
    return err("failed paramgen");
  return params;
}

/*
--- Fails with "failed keygen", "no parameters set" ---
EVP_PKEY *make_key(EVP_PKEY *params) {
  EVP_PKEY_CTX *keyctx = NULL;
  EVP_PKEY *key = NULL;
  keyctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (keyctx == NULL)
    return err("failed to make key ctx");
  if (1 != EVP_PKEY_keygen_init(keyctx))
    return err("failed to init key ctx");
  if (1 != EVP_PKEY_keygen(keyctx, &key))
    return err("failed keygen");
  if (key == NULL)
    return err("generated key is NULL");
  return key;
}
*/

EVP_PKEY *make_key(EVP_PKEY *params) {
  EC_KEY *ec = NULL;
  EVP_PKEY *key = NULL;

  ec = EVP_PKEY_get1_EC_KEY(params);
  if (ec == NULL) return err("no EC_KEY in params");
  ec = EC_KEY_dup(ec);
  if (ec == NULL) return err("failed to dup EC_KEY");

  if (1 != EC_KEY_generate_key(ec))
    return err("failed to generate key");
  key = EVP_PKEY_new();
  EVP_PKEY_set1_EC_KEY(key, ec);
  return key;
}

/* Convert private key to public-only key via PUBKEY */
EVP_PKEY *priv2pub(EVP_PKEY *privkey) {
  EVP_PKEY *pubkey = NULL;
  unsigned char *buf = NULL, *bufcopy = NULL;
  long bufsize = 0;

  bufsize = i2d_PUBKEY(privkey, &buf);
  if (bufsize <= 0)
    return err("i2d_PUBKEY failed");

  buf = malloc(bufsize);
  bufcopy = buf;

  i2d_PUBKEY(privkey, &bufcopy);

  bufcopy = buf;
  pubkey = d2i_PUBKEY(&pubkey, &bufcopy, bufsize);
  if (pubkey == NULL) 
    return err("public key is NULL");

  return pubkey;
}

/* Returns 0 if pubkey can verify signature created by privkey */
int test_keypair(EVP_PKEY *privkey, EVP_PKEY *pubkey) {
  EVP_MD_CTX *signctx = NULL, *verifyctx = NULL, *badverifyctx = NULL;
  char *msg = "Hello world!";
  char *badmsg = "I am the walrus.";
  unsigned char *sig = NULL;
  size_t siglen = 0;

  signctx = EVP_MD_CTX_create();
  EVP_DigestSignInit(signctx, NULL, EVP_sha256(), NULL, privkey);
  EVP_DigestSignUpdate(signctx, msg, strlen(msg));
  EVP_DigestSignFinal(signctx, NULL, &siglen);
  sig = malloc(siglen);
  EVP_DigestSignFinal(signctx, sig, &siglen);

  verifyctx = EVP_MD_CTX_create();
  EVP_DigestVerifyInit(verifyctx, NULL, EVP_sha256(), NULL, pubkey);
  EVP_DigestVerifyUpdate(verifyctx, msg, strlen(msg));
  if (1 != EVP_DigestVerifyFinal(verifyctx, sig, siglen)) {
    return (long) err("signature verification failed (didn't verify good signature)");
  }

  badverifyctx = EVP_MD_CTX_create();
  EVP_DigestVerifyInit(badverifyctx, NULL, EVP_sha256(), NULL, pubkey);
  EVP_DigestVerifyUpdate(badverifyctx, badmsg, strlen(badmsg));
  if (1 == EVP_DigestVerifyFinal(badverifyctx, sig, siglen)) {
    return (long) err("signature verification failed (verified bad signature)");
  }

  return 0;
}  

int derive_secret(EVP_PKEY *privkey, EVP_PKEY *peer_pubkey, unsigned char **out, size_t *outlen) {
  EVP_PKEY_CTX *dctx = NULL;
  
  check_err("*1*");

  dctx = EVP_PKEY_CTX_new(privkey, NULL);

  check_err("*2*");

  if (dctx == NULL)
    return (long) err("failed to make derivation ctx");

  check_err("*3*");

  if (1 != EVP_PKEY_derive_init(dctx))
    return (long) err("failed to init derivation ctx");

  check_err("*4*");

  if (1 != EVP_PKEY_derive_set_peer(dctx, peer_pubkey))
    return (long) err("failed to set peer key");

  check_err("*5*");

  if (1 != EVP_PKEY_derive(dctx, NULL, outlen))
    return (long) err("failed to get secret length");

  check_err("*6*");
  
  *out = malloc(*outlen);

  check_err("*7*");

  if (1 != EVP_PKEY_derive(dctx, *out, outlen))
    return (long) err("failed to derive secret");

  check_err("*8*");

  return 0;
}

void print_secret(unsigned char *buf, size_t len) {
  int i;
  for (i = 0; i < len; ++i) {
    printf("%02hhx", buf[i]);
  }
  printf("\n");
}

int runtest(char *curve_name, int curve_nid) {
  unsigned char *secret1 = NULL, *secret2 = NULL;
  size_t secret1_len = 0, secret2_len = 0;
  EVP_PKEY *params = NULL;
  EVP_PKEY *my_privkey = NULL, *my_pubkey = NULL;
  EVP_PKEY *peer_privkey = NULL;
  EVP_PKEY *peer_pubkey = NULL;

  printf("== Testing curve: %s (%d) ==\n", curve_name, curve_nid);

  params = make_params(curve_nid);
  my_privkey = make_key(params);
  peer_privkey = make_key(params);

  my_pubkey = priv2pub(my_privkey);
  peer_pubkey = priv2pub(peer_privkey);

  test_keypair(my_privkey, my_pubkey);
  test_keypair(peer_privkey, peer_pubkey);

  derive_secret(my_privkey, peer_pubkey, &secret1, &secret1_len);
  derive_secret(peer_privkey, my_pubkey, &secret2, &secret2_len);

  if (secret1_len != secret2_len) {
    printf("secret1_len = %ld\n", secret1_len);
    printf("secret2_len = %ld\n", secret2_len);
    printf("FAIL: secrets have different length: %ld, %ld\n\n", secret1_len, secret2_len);
    return 2;
  } else if (memcmp(secret1, secret2, secret1_len)) {
    printf("secret1 = ");
    print_secret(secret1, secret1_len);
    printf("secret2 = ");
    print_secret(secret2, secret2_len);
    printf("FAIL: secrets differ\n\n");
    return 2;
  } else {
    printf("OK\n\n");
    return 0;
  }
}

int main(int argc, char **argv) {
  ERR_load_crypto_strings();
  runtest("P-521", NID_secp521r1);
  runtest("P-384", NID_secp384r1);
  runtest("P-256", NID_X9_62_prime256v1);
  runtest("P-192", NID_X9_62_prime192v1);
  return 0;
}
