#include "seal.h"
#include "seal/seal.h"

SEALEncryptionParameters SEALEncryptionParametersBFV(void) {
  auto* params = new seal::EncryptionParameters(seal::scheme_type::BFV);
  params->set_poly_modulus_degree(2048);
  params->set_coeff_modulus(seal::coeff_modulus_128(2048));
  params->set_plain_modulus(1 << 8);
  return (void*)params;
}

SEALEncryptionParameters SEALEncryptionParametersCKKS(void) {
  auto* params = new seal::EncryptionParameters(seal::scheme_type::CKKS);
  params->set_poly_modulus_degree(8192);
  params->set_coeff_modulus(seal::coeff_modulus_128(8192));
  return (void*)params;
}

void SEALEncryptionParametersDelete(SEALEncryptionParameters p) {
  delete static_cast<seal::EncryptionParameters*>(p);
}

SEALContext SEALContextInit(SEALEncryptionParameters p) {
  auto* params = static_cast<seal::EncryptionParameters*>(p);
  auto ctx = seal::SEALContext::Create(*params);
  return (void*)new std::shared_ptr<seal::SEALContext>(std::move(ctx));
}

void SEALContextDelete(SEALContext c) {
  delete static_cast<std::shared_ptr<seal::SEALContext>*>(c);
}

SEALKeyGenerator SEALKeyGeneratorInit(SEALContext c) {
  auto* ctx = static_cast<std::shared_ptr<seal::SEALContext>*>(c);
  return (void*)new seal::KeyGenerator(*ctx);
}

void SEALKeyGeneratorDelete(SEALKeyGenerator g) {
  delete static_cast<seal::KeyGenerator*>(g);
}

SEALPublicKey SEALKeyGeneratorPublicKey(SEALKeyGenerator g) {
  auto* generator = static_cast<seal::KeyGenerator*>(g);
  auto key = generator->public_key();
  return (void*)new seal::PublicKey(key);
}

SEALSecretKey SEALKeyGeneratorSecretKey(SEALKeyGenerator g) {
  auto* generator = static_cast<seal::KeyGenerator*>(g);
  auto key = generator->secret_key();
  return (void*)new seal::SecretKey(key);
}

void SEALPublicKeyDelete(SEALPublicKey k) {
  delete static_cast<seal::PublicKey*>(k);
}

void SEALSecretKeyDelete(SEALSecretKey k) {
  delete static_cast<seal::SecretKey*>(k);
}

SEALEncryptor SEALEncryptorInit(SEALContext c, SEALPublicKey k) {
  auto* ctx = static_cast<std::shared_ptr<seal::SEALContext>*>(c);
  auto* key = static_cast<seal::PublicKey*>(k);
  return (void*)new seal::Encryptor(*ctx, *key);
}

void SEALEncryptorDelete(SEALEncryptor k) {
  delete static_cast<seal::Encryptor*>(k);
}

void SEALCiphertextDelete(SEALCiphertext k) {
  delete static_cast<seal::Ciphertext*>(k);
}

SEALCiphertext SEALEncryptorEncrypt(SEALEncryptor k, SEALPlaintext p) {
  auto* e = static_cast<seal::Encryptor*>(k);
  auto* pl = static_cast<seal::Plaintext*>(p);
  seal::Ciphertext encrypted;
  e->encrypt(*pl, encrypted);
  return (void*)new seal::Ciphertext(encrypted);
}

SEALEvaluator SEALEvaluatorInit(SEALContext c) {
  auto* ctx = static_cast<std::shared_ptr<seal::SEALContext>*>(c);
  return (void*)new seal::Evaluator(*ctx);
}

void SEALEvaluatorDelete(SEALEvaluator k) {
  delete static_cast<seal::Evaluator*>(k);
}

SEALDecryptor SEALDecryptorInit(SEALContext c, SEALSecretKey k) {
  auto* ctx = static_cast<std::shared_ptr<seal::SEALContext>*>(c);
  auto* key = static_cast<seal::SecretKey*>(k);
  return (void*)new seal::Decryptor(*ctx, *key);
}

void SEALDecryptorDelete(SEALDecryptor k) {
  delete static_cast<seal::Decryptor*>(k);
}

SEALPlaintext SEALDecryptorDecrypt(SEALDecryptor k, SEALCiphertext c) {
  auto* d = static_cast<seal::Decryptor*>(k);
  auto* ciphertext = static_cast<seal::Ciphertext*>(c);
  seal::Plaintext plain;
  d->decrypt(*ciphertext, plain);
  return (void*)new seal::Plaintext(plain);
}

SEALDecryptor SEALBinaryFractionalEncoderInit(SEALEncryptionParameters params) {
  auto* p = static_cast<seal::EncryptionParameters*>(params);
  return (void*)new seal::BinaryFractionalEncoder(
      p->plain_modulus(), p->poly_modulus_degree(),
      p->poly_modulus_degree() / 2 - 1, p->poly_modulus_degree() / 2 - 1);
}

void SEALBinaryFractionalEncoderDelete(SEALBinaryFractionalEncoder k) {
  delete static_cast<seal::BinaryFractionalEncoder*>(k);
}

SEALPlaintext SEALBinaryFractionalEncoderEncode(SEALBinaryFractionalEncoder k,
                                                double a) {
  auto* e = static_cast<seal::BinaryFractionalEncoder*>(k);
  return (void*)new seal::Plaintext(e->encode(a));
}

double SEALBinaryFractionalEncoderDecode(SEALBinaryFractionalEncoder k,
                                         SEALPlaintext a) {
  auto* e = static_cast<seal::BinaryFractionalEncoder*>(k);
  auto* p = static_cast<seal::Plaintext*>(a);
  return e->decode(*p);
}

void SEALPlaintextDelete(SEALPlaintext k) {
  delete static_cast<seal::Plaintext*>(k);
}

SEALCKKSEncoder SEALCKKSEncoderInit(SEALContext c) {
  auto* ctx = static_cast<std::shared_ptr<seal::SEALContext>*>(c);
  return (void*)new seal::CKKSEncoder(*ctx);
}

void SEALCKKSEncoderDelete(SEALCKKSEncoder k) {
  delete static_cast<seal::CKKSEncoder*>(k);
}

SEALPlaintext SEALCKKSEncoderEncode(SEALCKKSEncoder k, double num,
                                    double scale) {
  auto* e = static_cast<seal::CKKSEncoder*>(k);
  std::vector<double> data{num};
  seal::Plaintext p;
  e->encode(data, scale, p);
  return (void*)new seal::Plaintext(p);
}

double SEALCKKSEncoderDecode(SEALCKKSEncoder k, SEALPlaintext p) {
  auto* e = static_cast<seal::CKKSEncoder*>(k);
  auto* plain = static_cast<seal::Plaintext*>(p);
  std::vector<double> data(1);
  e->decode(*plain, data);
  return data.at(0);
}
