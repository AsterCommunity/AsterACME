//! PKCS#12 ([RFC 7292](https://datatracker.ietf.org/doc/html/rfc7292)) bundle
//! construction for deployment publication.
//!
//! The container is hand-assembled on the `der` types: certificate bags are
//! published in plaintext, the private key is protected with PBES2
//! (PBKDF2-HMAC-SHA256 into AES-256-CBC), and the whole bundle is integrity
//! protected with an HMAC-SHA256 MAC whose key derives through the legacy
//! [RFC 7292 Appendix B](https://datatracker.ietf.org/doc/html/rfc7292#appendix-B)
//! KDF required by interoperating PKCS#12 consumers. No private key material or
//! password is retained alongside the returned bundle; callers pass `Zeroizing` inputs.

use crate::issuance::{IssueError, failure};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit as _, generic_array::GenericArray};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::{
    Any, Decode as _, Encode as _, Sequence, Tag, ValueOrd,
    asn1::{Null, ObjectIdentifier, OctetString, SetOfVec},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

const MAC_ITERATIONS: u32 = 2048;
const PBKDF2_ITERATIONS: u32 = 2048;
const MAC_KEY_LEN: usize = 32;
const PBES2_KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const LOCAL_KEY_ID_LEN: usize = 20;
const MAX_PASSWORD_FILE: usize = 4096;
pub(super) const MAX_PASSWORD_ENV: usize = 512;

const OID_PKCS7_DATA: &str = "1.2.840.113549.1.7.1";
const OID_CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const OID_PKCS8_SHROUDED_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.2";
const OID_X509_CERTIFICATE: &str = "1.2.840.113549.1.9.22.1";
const OID_FRIENDLY_NAME: &str = "1.2.840.113549.1.9.20";
const OID_LOCAL_KEY_ID: &str = "1.2.840.113549.1.9.21";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_HMAC_WITH_SHA256: &str = "1.2.840.113549.2.9";
const OID_PBES2: &str = "1.2.840.113549.1.5.13";
const OID_PBKDF2: &str = "1.2.840.113549.1.5.12";
const OID_AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";

/// Parse a static OID string; every call site uses a compile-time constant.
fn oid(value: &str) -> Result<ObjectIdentifier, IssueError> {
    ObjectIdentifier::new(value).map_err(|_| failure("static PKCS#12 OID must parse"))
}

/// Resolve the PKCS#12 password for a binding that publishes a bundle.
///
/// Exactly one source must be present. The raw password is zeroized on drop;
/// the bundle builder uses UTF-8 for PBES2 and BMP encoding for the MAC.
///
/// # Errors
/// Reports a missing or empty environment value, an unreadable password file,
/// a password outside the Unicode BMP, or an ambiguous/absent source.
pub(super) fn resolve_password(
    env: Option<&str>,
    file: Option<&Path>,
) -> Result<Zeroizing<String>, IssueError> {
    let password = match (env, file) {
        (Some(name), None) => read_env_password(name)?,
        (None, Some(path)) => read_file_password(path)?,
        (Some(_), Some(_)) => {
            return Err(failure(
                "choose one PKCS#12 password source, not both env and file",
            ));
        }
        (None, None) => {
            return Err(failure(
                "this deployment publishes a PKCS#12 bundle but has no password source; rerun interactively or configure one with cert deploy update",
            ));
        }
    };
    bmp_password(&password)?;
    Ok(password)
}

/// Validate an explicitly supplied password and encode it for the RFC 7292 KDF.
///
/// # Errors
/// Rejects empty passwords, NUL and characters outside the Unicode BMP.
pub(super) fn bmp_password(password: &str) -> Result<Zeroizing<Vec<u8>>, IssueError> {
    if password.is_empty() {
        return Err(failure(
            "PKCS#12 password source resolved to an empty value",
        ));
    }
    if password.chars().any(|c| u32::from(c) > 0xFFFF || c == '\0') {
        return Err(failure(
            "PKCS#12 password contains characters outside the Unicode BMP or contains NUL",
        ));
    }
    Ok(bmp_string(password))
}

fn read_env_password(name: &str) -> Result<Zeroizing<String>, IssueError> {
    if name.is_empty()
        || name.len() > MAX_PASSWORD_ENV
        || !name.is_ascii()
        || name.bytes().any(|b| b.is_ascii_control() || b == b'=')
    {
        return Err(failure(
            "invalid PKCS#12 password environment variable name",
        ));
    }
    std::env::var(name)
        .map(Zeroizing::new)
        .map_err(|_| {
            failure(&format!(
                "PKCS#12 password source env '{name}' is unavailable; configure it for the daemon environment or switch to a password file"
            ))
        })
}

fn read_file_password(path: &Path) -> Result<Zeroizing<String>, IssueError> {
    let bytes = crate::state_file::read_external_private(path, MAX_PASSWORD_FILE)
        .map_err(|_| failure("PKCS#12 password file is missing or unreadable"))?;
    let line = match bytes.iter().position(|byte| *byte == b'\n') {
        Some(end) => bytes[..end].strip_suffix(b"\r").unwrap_or(&bytes[..end]),
        None => bytes.as_slice(),
    };
    let line = std::str::from_utf8(line)
        .map_err(|_| failure("PKCS#12 password file is not valid UTF-8"))?;
    Ok(Zeroizing::new(line.to_owned()))
}

/// Assemble the bundle from the leaf certificate, its CA chain (PEM), the
/// PKCS#8 private key and the password (UTF-8 for PBES2, BMP for the MAC).
///
/// # Errors
/// Reports malformed certificate PEM, unsupported key sizes and encoding or
/// randomness failures. Failure details never contain the password or key.
pub(super) fn build_pkcs12(
    leaf_der: &[u8],
    ca_chain_pem: &[u8],
    key_pk8: &[u8],
    friendly_name: &str,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>, IssueError> {
    let mac_password = bmp_password(password)?;
    let mut random = [0u8; SALT_LEN + SALT_LEN + IV_LEN];
    aws_lc_rs::rand::fill(&mut random)
        .map_err(|_| failure("cannot obtain randomness for PKCS#12 bundle"))?;
    let (mac_salt, rest) = random.split_at(SALT_LEN);
    let (key_salt, iv) = rest.split_at(SALT_LEN);

    let mut cert_bags: Vec<SafeBag> = Vec::new();
    cert_bags.push(cert_bag(
        leaf_der,
        friendly_name,
        Some(&local_key_id(leaf_der)),
    )?);
    for der in pem_certificates(ca_chain_pem)? {
        cert_bags.push(cert_bag(&der, friendly_name, None)?);
    }

    let key_bag = encrypted_key_bag(key_pk8, friendly_name, leaf_der, password, key_salt, iv)?;

    let auth_safe = vec![
        data_content_info(
            cert_bags
                .to_der()
                .map_err(|_| failure("cannot encode PKCS#12 certificate bags"))?,
        )?,
        data_content_info(
            vec![key_bag]
                .to_der()
                .map_err(|_| failure("cannot encode PKCS#12 key bags"))?,
        )?,
    ];
    let auth_safe_der = auth_safe
        .to_der()
        .map_err(|_| failure("cannot encode PKCS#12 authenticated safe"))?;

    let mac_key = pkcs12_kdf(&mac_password, mac_salt, 3, MAC_ITERATIONS, MAC_KEY_LEN);
    let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key)
        .map_err(|_| failure("cannot derive PKCS#12 MAC key"))?;
    mac.update(&auth_safe_der);
    let mac_bytes = mac.finalize().into_bytes();

    let pfx = Pfx {
        version: 3,
        auth_safe: data_content_info(auth_safe_der)?,
        mac_data: Some(MacData {
            mac: DigestInfo {
                algorithm: NullAlgorithm {
                    algorithm: oid(OID_SHA256)?,
                    parameters: Null,
                },
                digest: OctetString::new(mac_bytes.to_vec())
                    .map_err(|_| failure("invalid PKCS#12 MAC"))?,
            },
            mac_salt: OctetString::new(mac_salt.to_vec())
                .map_err(|_| failure("invalid PKCS#12 MAC salt"))?,
            iterations: MAC_ITERATIONS,
        }),
    };
    Ok(Zeroizing::new(
        pfx.to_der()
            .map_err(|_| failure("cannot encode PKCS#12 bundle"))?,
    ))
}

fn encrypted_key_bag(
    key_pk8: &[u8],
    friendly_name: &str,
    leaf_der: &[u8],
    password: &str,
    key_salt: &[u8],
    iv: &[u8],
) -> Result<SafeBag, IssueError> {
    let enc_key = pbkdf2_sha256(
        password.as_bytes(),
        key_salt,
        PBKDF2_ITERATIONS,
        PBES2_KEY_LEN,
    )?;
    let encrypted = aes256_cbc_encrypt(&enc_key, iv, key_pk8)?;
    Ok(SafeBag {
        id: oid(OID_PKCS8_SHROUDED_KEY_BAG)?,
        value: Any::from_der(
            &EncryptedPrivateKeyInfo {
                algorithm: Pbes2Algorithm {
                    algorithm: oid(OID_PBES2)?,
                    parameters: Pbes2Params {
                        key_derivation_func: Pbkdf2Algorithm {
                            algorithm: oid(OID_PBKDF2)?,
                            parameters: Pbkdf2Params {
                                salt: OctetString::new(key_salt.to_vec())
                                    .map_err(|_| failure("invalid PKCS#12 salt"))?,
                                iteration_count: PBKDF2_ITERATIONS,
                                prf: Some(NullAlgorithm {
                                    algorithm: oid(OID_HMAC_WITH_SHA256)?,
                                    parameters: Null,
                                }),
                            },
                        },
                        encryption_scheme: IvAlgorithm {
                            algorithm: oid(OID_AES256_CBC)?,
                            parameters: OctetString::new(iv.to_vec())
                                .map_err(|_| failure("invalid PKCS#12 IV"))?,
                        },
                    },
                },
                encrypted_data: OctetString::new(encrypted)
                    .map_err(|_| failure("invalid PKCS#12 encrypted key"))?,
            }
            .to_der()
            .map_err(|_| failure("cannot encode PKCS#12 key bag"))?,
        )
        .map_err(|_| failure("cannot encode PKCS#12 key bag"))?,
        attributes: Some(attributes_into_set(vec![
            string_attribute(
                OID_FRIENDLY_NAME,
                Tag::BmpString,
                &friendly_name
                    .encode_utf16()
                    .flat_map(u16::to_be_bytes)
                    .collect::<Vec<_>>(),
            )?,
            string_attribute(OID_LOCAL_KEY_ID, Tag::OctetString, &local_key_id(leaf_der))?,
        ])?),
    })
}
fn cert_bag(
    certificate_der: &[u8],
    friendly_name: &str,
    local_key_id: Option<&[u8]>,
) -> Result<SafeBag, IssueError> {
    let mut attributes: Vec<Pkcs12Attribute> = vec![string_attribute(
        OID_FRIENDLY_NAME,
        Tag::BmpString,
        &friendly_name
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>(),
    )?];
    if let Some(local_key_id) = local_key_id {
        attributes.push(string_attribute(
            OID_LOCAL_KEY_ID,
            Tag::OctetString,
            local_key_id,
        )?);
    }
    Ok(SafeBag {
        id: oid(OID_CERT_BAG)?,
        value: Any::from_der(
            &CertBag {
                cert_id: oid(OID_X509_CERTIFICATE)?,
                cert_value: Any::new(Tag::OctetString, certificate_der.to_vec())
                    .map_err(|_| failure("invalid PKCS#12 certificate"))?,
            }
            .to_der()
            .map_err(|_| failure("cannot encode PKCS#12 certificate bag"))?,
        )
        .map_err(|_| failure("cannot encode PKCS#12 certificate bag"))?,
        attributes: Some(attributes_into_set(attributes)?),
    })
}

/// Insert attributes into the canonical DER-ordered set.
fn attributes_into_set(
    attributes: Vec<Pkcs12Attribute>,
) -> Result<SetOfVec<Pkcs12Attribute>, IssueError> {
    let mut set = SetOfVec::new();
    for attribute in attributes {
        set.insert(attribute)
            .map_err(|_| failure("cannot encode PKCS#12 attributes"))?;
    }
    Ok(set)
}

fn string_attribute(id: &str, tag: Tag, value: &[u8]) -> Result<Pkcs12Attribute, IssueError> {
    let mut values = SetOfVec::new();
    values
        .insert(Any::new(tag, value.to_vec()).map_err(|_| failure("invalid PKCS#12 attribute"))?)
        .map_err(|_| failure("invalid PKCS#12 attribute"))?;
    Ok(Pkcs12Attribute {
        attr_id: oid(id)?,
        attr_values: values,
    })
}

fn local_key_id(certificate_der: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(certificate_der);
    digest[..LOCAL_KEY_ID_LEN].to_vec()
}

fn data_content_info(payload: Vec<u8>) -> Result<ContentInfo, IssueError> {
    Ok(ContentInfo {
        content_type: oid(OID_PKCS7_DATA)?,
        content: Any::new(Tag::OctetString, payload)
            .map_err(|_| failure("cannot encode PKCS#12 content"))?,
    })
}

fn pem_certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>, IssueError> {
    let text = std::str::from_utf8(pem).map_err(|_| failure("CA chain PEM is not valid UTF-8"))?;
    let mut ders = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        if !rest[..start].trim().is_empty() {
            return Err(failure("CA chain PEM contains non-certificate content"));
        }
        let Some(end) = rest[start..].find("-----END CERTIFICATE-----") else {
            return Err(failure("CA chain PEM contains an unterminated certificate"));
        };
        let body = rest[start + "-----BEGIN CERTIFICATE-----".len()..start + end]
            .bytes()
            .filter(u8::is_ascii_graphic)
            .collect::<Vec<u8>>();
        let der = STANDARD
            .decode(&body)
            .map_err(|_| failure("CA chain PEM contains invalid base64"))?;
        ders.push(der);
        rest = &rest[start + end + "-----END CERTIFICATE-----".len()..];
    }
    if rest.bytes().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(failure("CA chain PEM contains non-certificate content"));
    }
    Ok(ders)
}

/// RFC 7292 `BMPString`: UTF-16BE with two terminating NUL bytes.
fn bmp_string(value: &str) -> Zeroizing<Vec<u8>> {
    let mut bytes: Vec<u8> = value.encode_utf16().flat_map(u16::to_be_bytes).collect();
    bytes.extend([0u8; 2]);
    Zeroizing::new(bytes)
}

/// The legacy RFC 7292 Appendix B.2 KDF. `id` diversifies encryption keys (1),
/// IVs (2) and MAC keys (3) from one password.
fn pkcs12_kdf(pass: &[u8], salt: &[u8], id: u8, rounds: u32, key_len: usize) -> Zeroizing<Vec<u8>> {
    // SHA-256 fixed parameters: 64-byte input blocks, 32-byte outputs.
    let block_size = 64;
    let output_size = 32;
    let id_block = vec![id; block_size];
    let slen = block_size * salt.len().div_ceil(block_size);
    let plen = block_size * pass.len().div_ceil(block_size);
    let ilen = slen + plen;
    let mut i_bytes = Zeroizing::new(vec![0u8; ilen]);
    for (index, slot) in i_bytes.iter_mut().take(slen).enumerate() {
        *slot = salt[index % salt.len()];
    }
    for (index, slot) in i_bytes.iter_mut().skip(slen).take(plen).enumerate() {
        *slot = pass[index % pass.len()];
    }
    let mut out = Zeroizing::new(vec![0u8; key_len]);
    let mut n = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(&id_block);
        hasher.update(i_bytes.as_slice());
        let mut a = Zeroizing::new(hasher.finalize_reset().to_vec());
        for _ in 1..rounds {
            let mut hasher = Sha256::new();
            hasher.update(a.as_slice());
            a.copy_from_slice(&hasher.finalize());
        }
        let take = (key_len - n).min(output_size);
        out[n..n + take].copy_from_slice(&a[..take]);
        n += take;
        if n == key_len {
            break;
        }
        let mut j = 0;
        while j < ilen {
            let mut carry = 1u16;
            let mut k = block_size - 1;
            loop {
                carry += u16::from(i_bytes[j + k]) + u16::from(a[k % output_size]);
                i_bytes[j + k] = (carry & 0xff) as u8;
                carry >>= 8;
                if k == 0 {
                    break;
                }
                k -= 1;
            }
            j += block_size;
        }
    }
    out
}

/// PBKDF2-HMAC-SHA256 (RFC 8018) over the shared hmac/sha2 stack.
fn pbkdf2_sha256(
    pass: &[u8],
    salt: &[u8],
    rounds: u32,
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>, IssueError> {
    let mut block_index: u32 = 1;
    let mut out = Zeroizing::new(Vec::with_capacity(key_len));
    while out.len() < key_len {
        let mut mac = Hmac::<Sha256>::new_from_slice(pass)
            .map_err(|_| failure("cannot derive PKCS#12 encryption key"))?;
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = Zeroizing::new(mac.finalize().into_bytes().to_vec());
        let mut t = Zeroizing::new(u.to_vec());
        for _ in 1..rounds {
            let mut mac = Hmac::<Sha256>::new_from_slice(pass)
                .map_err(|_| failure("cannot derive PKCS#12 encryption key"))?;
            mac.update(&u);
            u.copy_from_slice(&mac.finalize().into_bytes());
            for (t_byte, u_byte) in t.iter_mut().zip(u.iter()) {
                *t_byte ^= *u_byte;
            }
        }
        out.extend_from_slice(&t);
        block_index += 1;
    }
    out.truncate(key_len);
    Ok(out)
}

/// AES-256-CBC with PKCS#7 padding, hand-rolled on the `aes` block primitive.
fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IssueError> {
    let cipher = Aes256::new_from_slice(key)
        .map_err(|_| failure("invalid PKCS#12 encryption key length"))?;
    let pad = u8::try_from(16 - (plaintext.len() % 16))
        .map_err(|_| failure("invalid PKCS#12 padding"))?;
    let mut padded = Zeroizing::new(Vec::with_capacity(plaintext.len() + usize::from(pad)));
    padded.extend_from_slice(plaintext);
    padded.extend(std::iter::repeat_n(pad, usize::from(pad)));
    let mut previous = GenericArray::clone_from_slice(
        <&[u8; 16]>::try_from(iv).map_err(|_| failure("invalid PKCS#12 IV length"))?,
    );
    for chunk in padded.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        for (byte, previous_byte) in block.iter_mut().zip(previous.iter()) {
            *byte ^= *previous_byte;
        }
        cipher.encrypt_block(block);
        previous = *block;
    }
    Ok(padded.to_vec())
}

// --- ASN.1 model; structured parameters are typed so `der` writes their headers ---

#[derive(Sequence)]
struct Pfx {
    version: u8,
    auth_safe: ContentInfo,
    #[asn1(optional = "true")]
    mac_data: Option<MacData>,
}

#[derive(Sequence)]
struct ContentInfo {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", constructed = "true")]
    content: Any,
}

#[derive(Sequence)]
struct MacData {
    mac: DigestInfo,
    mac_salt: OctetString,
    iterations: u32,
}

#[derive(Sequence)]
struct DigestInfo {
    algorithm: NullAlgorithm,
    digest: OctetString,
}

/// `AlgorithmIdentifier` whose parameter is an explicit `NULL` (sha256, hmacWithSHA256).
#[derive(Sequence)]
struct NullAlgorithm {
    algorithm: ObjectIdentifier,
    parameters: Null,
}

#[derive(Sequence)]
struct Pbes2Algorithm {
    algorithm: ObjectIdentifier,
    parameters: Pbes2Params,
}

#[derive(Sequence)]
struct Pbkdf2Algorithm {
    algorithm: ObjectIdentifier,
    parameters: Pbkdf2Params,
}

#[derive(Sequence)]
struct IvAlgorithm {
    algorithm: ObjectIdentifier,
    parameters: OctetString,
}

#[derive(Sequence)]
struct SafeBag {
    id: ObjectIdentifier,
    #[asn1(context_specific = "0", constructed = "true")]
    value: Any,
    #[asn1(optional = "true")]
    attributes: Option<SetOfVec<Pkcs12Attribute>>,
}

#[derive(Sequence, ValueOrd)]
struct Pkcs12Attribute {
    attr_id: ObjectIdentifier,
    attr_values: SetOfVec<Any>,
}

#[derive(Sequence)]
struct CertBag {
    cert_id: ObjectIdentifier,
    #[asn1(context_specific = "0", constructed = "true")]
    cert_value: Any,
}

#[derive(Sequence)]
struct EncryptedPrivateKeyInfo {
    algorithm: Pbes2Algorithm,
    encrypted_data: OctetString,
}

#[derive(Sequence)]
struct Pbes2Params {
    key_derivation_func: Pbkdf2Algorithm,
    encryption_scheme: IvAlgorithm,
}

#[derive(Sequence)]
struct Pbkdf2Params {
    salt: OctetString,
    iteration_count: u32,
    #[asn1(optional = "true")]
    prf: Option<NullAlgorithm>,
}

#[cfg(test)]
mod tests;
