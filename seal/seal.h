#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* SEALContext;
typedef void* SEALKeyGenerator;
typedef void* SEALPublicKey;
typedef void* SEALSecretKey;
typedef void* SEALEncryptor;
typedef void* SEALDecryptor;
typedef void* SEALEvaluator;
typedef void* SEALIntegerEncoder;
typedef void* SEALBinaryFractionalEncoder;
typedef void* SEALPlaintext;
typedef void* SEALEncryptionParameters;
typedef void* SEALCKKSEncoder;
typedef void* SEALCiphertext;
typedef void* SEALRelinKeys;

SEALEncryptionParameters SEALEncryptionParametersBFV(void);
SEALEncryptionParameters SEALEncryptionParametersCKKS(void);
void SEALEncryptionParametersDelete(SEALEncryptionParameters);

SEALContext SEALContextInit(SEALEncryptionParameters);
void SEALContextDelete(SEALContext);

SEALKeyGenerator SEALKeyGeneratorInit(SEALContext);
void SEALKeyGeneratorDelete(SEALKeyGenerator);
SEALPublicKey SEALKeyGeneratorPublicKey(SEALKeyGenerator);
SEALSecretKey SEALKeyGeneratorSecretKey(SEALKeyGenerator);
SEALRelinKeys SEALKeyGeneratorRelinKeys(SEALKeyGenerator, int);

void SEALPublicKeyDelete(SEALPublicKey);
void SEALSecretKeyDelete(SEALSecretKey);
void SEALRelinKeysDelete(SEALRelinKeys);

SEALEncryptor SEALEncryptorInit(SEALContext, SEALPublicKey);
void SEALEncryptorDelete(SEALEncryptor);
SEALCiphertext SEALEncryptorEncrypt(SEALEncryptor, SEALPlaintext);

SEALEvaluator SEALEvaluatorInit(SEALContext);
void SEALEvaluatorDelete(SEALEvaluator);

void SEALEvaluatorSquareInplace(SEALEvaluator, SEALCiphertext);
void SEALEvaluatorNegateInplace(SEALEvaluator, SEALCiphertext);
void SEALEvaluatorAddInplace(SEALEvaluator, SEALCiphertext, SEALCiphertext);
void SEALEvaluatorAddPlainInplace(SEALEvaluator, SEALCiphertext, SEALPlaintext);
void SEALEvaluatorSubInplace(SEALEvaluator, SEALCiphertext, SEALCiphertext);
void SEALEvaluatorSubPlainInplace(SEALEvaluator, SEALCiphertext, SEALPlaintext);
void SEALEvaluatorMultiplyInplace(SEALEvaluator, SEALCiphertext,
                                  SEALCiphertext);
void SEALEvaluatorMultiplyPlainInplace(SEALEvaluator, SEALCiphertext,
                                       SEALPlaintext);
void SEALEvaluatorRelinearizeInplace(SEALEvaluator, SEALCiphertext,
                                     SEALRelinKeys);

SEALDecryptor SEALDecryptorInit(SEALContext, SEALSecretKey);
void SEALDecryptorDelete(SEALDecryptor);
SEALPlaintext SEALDecryptorDecrypt(SEALDecryptor, SEALCiphertext);

SEALBinaryFractionalEncoder SEALBinaryFractionalEncoderInit(
    SEALEncryptionParameters);
void SEALBinaryFractionalEncoderDelete(SEALBinaryFractionalEncoder);
SEALPlaintext SEALBinaryFractionalEncoderEncode(SEALBinaryFractionalEncoder,
                                                double);
double SEALBinaryFractionalEncoderDecode(SEALBinaryFractionalEncoder,
                                         SEALPlaintext);

void SEALPlaintextDelete(SEALPlaintext);

SEALCKKSEncoder SEALCKKSEncoderInit(SEALContext);
SEALPlaintext SEALCKKSEncoderEncode(SEALCKKSEncoder, double, double);
double SEALCKKSEncoderDecode(SEALCKKSEncoder, SEALPlaintext);
void SEALCKKSEncoderDelete(SEALCKKSEncoder);

void SEALCiphertextDelete(SEALCiphertext);
SEALCiphertext SEALCiphertextCopy(SEALCiphertext);

#ifdef __cplusplus
} /* end extern "C" */
#endif
