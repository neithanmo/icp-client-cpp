#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum IdentityType {
  /**
   * anonym
   */
  Anonym = 0,
  /**
   * basic
   */
  Basic = 1,
  /**
   * secp256k1
   */
  Secp256k1 = 2,
} IdentityType;

typedef struct FFIAgent FFIAgent;

typedef struct PrincipalRet_u8 {
  uint8_t *ptr;
  uintptr_t len;
} PrincipalRet_u8;

/**
 * Ptr creation with size and len
 */
typedef void (*RetPtr_u8)(const uint8_t*, int);

/**
 * Creates a new RequestId from a SHA-256 hash.
 */
char *request_id_new(const uint8_t *bytes, int bytes_len);

/**
 * Construct a Principal of the IC management canister
 */
struct PrincipalRet_u8 principal_management_canister(void);

/**
 * Construct a self-authenticating ID from public key
 */
struct PrincipalRet_u8 principal_self_authenticating(const uint8_t *public_key, int public_key_len);

/**
 * Construct an anonymous ID
 */
struct PrincipalRet_u8 principal_anonymous(void);

/**
 * Construct a Principal from a slice of bytes.
 */
struct PrincipalRet_u8 principal_from_slice(const uint8_t *bytes, int bytes_len);

/**
 * Construct a Principal from a slice of bytes.
 */
struct PrincipalRet_u8 principal_try_from_slice(const uint8_t *bytes,
                                                int bytes_len,
                                                RetPtr_u8 error_ret);

/**
 * Parse a Principal from text representation.
 */
struct PrincipalRet_u8 principal_from_text(const char *text, RetPtr_u8 error_ret);

/**
 * Return the textual representation of Principal.
 */
struct PrincipalRet_u8 principal_to_text(const uint8_t *bytes,
                                         const int *bytes_len,
                                         RetPtr_u8 error_ret);

void principal_free(uint8_t *ptr);

/**
 * Dummy
 */
enum IdentityType identity_type(enum IdentityType id_type);

/**
 * The anonymous identity.
 */
char *identity_anonymous(void);

/**
 * Create a BasicIdentity from reading a PEM Content
 */
char *identity_basic_from_pem(const char *pem_data, RetPtr_u8 error_ret);

/**
 * Create a BasicIdentity from a KeyPair from the ring crate.
 */
char *identity_basic_from_key_pair(const uint8_t *public_key,
                                   const uint8_t *private_key_seed,
                                   RetPtr_u8 error_ret);

/**
 * Creates an identity from a PEM certificate.
 */
char *identity_secp256k1_from_pem(const char *pem_data, RetPtr_u8 error_ret);

/**
 * Creates an identity from a private key.
 */
char *identity_secp256k1_from_private_key(const char *private_key, uintptr_t pk_len);

/**
 * Returns a sender, ie. the Principal ID that is used to sign a request.
 * Only one sender can be used per request.
 */
char *identity_sender(char *id_ptr, enum IdentityType idType, RetPtr_u8 error_ret);

/**
 * Sign a blob, the concatenation of the domain separator & request ID,
 * creating the sender signature.>
 */
char *identity_sign(const uint8_t *bytes,
                    int bytes_len,
                    char *id_ptr,
                    enum IdentityType idType,
                    RetPtr_u8 pubkey_ret,
                    RetPtr_u8 error_ret);

void identity_free(char *ptr);

/**
 * Creates a FFIAgent instance to be used on the remaining agent functions
 */
struct FFIAgent *agent_create_wrap(const char *path,
                                   const char *identity,
                                   enum IdentityType id_type,
                                   const uint8_t *canister_id,
                                   int canister_id_len,
                                   const char *did_content,
                                   RetPtr_u8 error_ret);

/**
 * Calls and returns the information returned by the status endpoint of a replica.
 */
char *agent_status_wrap(const struct FFIAgent *agent_ptr, RetPtr_u8 error_ret);

/**
 * Calls and returns a query call to the canister.
 */
char *agent_query_wrap(const struct FFIAgent *agent_ptr,
                       const char *method,
                       const char *method_args,
                       RetPtr_u8 error_ret);

/**
 * Calls and returns a update call to the canister.
 */
char *agent_update_wrap(const struct FFIAgent *agent_ptr,
                        const char *method,
                        const char *method_args,
                        RetPtr_u8 error_ret);

void agent_free(const struct FFIAgent *agent);

char *idl_args_to_text(const void *idl_args);

const void *idl_args_from_text(const char *text, RetPtr_u8 error_ret);
