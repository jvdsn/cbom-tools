import argparse
import json
import re


CNSA1_0_MIN_MODULUS = 3072
CNSA1_0_GROUPS = ("ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192", "MODP-3072", "MODP-4096", "MODP-6144", "MODP-8192")

ENISA2_0_AES_MODES = ("CTR", "OFB", "CBC", "CTS", "CFB1", "CFB64", "CFB128" "XTS", "CCM", "GCM", "EAX", "SIV", "KW", "KWP", "CMAC", "GMAC")
ENISA2_0_MIN_MODULUS = 3000
ENISA2_0_GROUPS = ("ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192", "MODP-3072", "MODP-4096", "MODP-6144", "MODP-8192")
ENISA2_0_CURVES = ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "P-256", "P-384", "P-521", "FRP256v1")
ENISA2_0_SLH_DSA = ("SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f")

def check_hash(name, prefix, hashes):
    for hash in hashes:
        if name == f"{prefix}-{hash}" or name.startswith(f"{prefix}-{hash}-"):
            return True, None
    return False, f"{prefix} must use a hash in {hashes}"

def check_curve(name, prefix, curves):
    for curve in curves:
        if name == f"{prefix}-{curve}" or name.startswith(f"{prefix}-{curve}-"):
            return True, None
    return False, f"{prefix} must use a curve in {curves}"

def check_aes(name, prefix, key_bits, modes):
    for bits in key_bits:
        if name == f"{prefix}-{bits}":
            return True, None
        if name.startswith(f"{prefix}-{bits}"):
            for mode in modes:
                if name == f"{prefix}-{bits}-{mode}" or name.startswith(f"{prefix}-{bits}-{mode}-"):
                    return True, None
            return False, f"{prefix} must use a mode in {modes}"
    return False, f"{prefix} must use a key size in {key_bits}"

def check_ecdsa(name, curves, hashes):
    for curve in curves:
        if name == f"ECDSA-{curve}":
            return True, None
        if name.startswith(f"ECDSA-{curve}"):
            return check_hash(name, f"ECDSA-{curve}", hashes)
    return False, f"ECDSA must use a curve in {curves}"

def check_ffdh(name, groups):
    for group in groups:
        if name == f"FFDH-{group}" or name == f"FFDHE-{group}":
            return True, None
    return False, f"FFDH must use a group in {groups}"

def check_oaep(name, hashes, mgfs, min_modulus_bits):
    for hash in hashes:
        if name.startswith(f"RSA-OAEP-{hash}-"):
            for mgf in mgfs:
                if name.startswith(f"RSA-OAEP-{hash}-{mgf}-"):
                    match = re.fullmatch(rf"RSA-OAEP-{hash}-{mgf}-(\d+)", name)
                    if match and int(match.group(1)) >= min_modulus_bits:
                        return True, None
                    return False, f"RSA-OAEP must use a modulus >= {min_modulus_bits} bits"
            return False, f"RSA-OAEP must use a MGF in {mgfs}"
    return False, f"RSA-OAEP must use a hash in {hashes}"

def check_pss(name, hashes, mgfs, min_modulus_bits):
    for hash in hashes:
        if name.startswith(f"RSA-PSS-{hash}-"):
            for mgf in mgfs:
                if name.startswith(f"RSA-PSS-{hash}-{mgf}-"):
                    match = re.fullmatch(rf"RSA-PSS-{hash}-{mgf}-\d+-(\d+)", name)
                    if match and int(match.group(1)) >= min_modulus_bits:
                        return True, None
                    return False, f"RSA-PSS must use a modulus >= {min_modulus_bits} bits"
            return False, f"RSA-PSS must use a MGF in {mgfs}"
    return False, f"RSA-PSS must use a hash in {hashes}"

def check_rsa(name, min_modulus_bits):
    match = re.fullmatch(fr"RSA-(\d+)", name)
    if match and int(match.group(1)) >= min_modulus_bits:
        return True, None
    return False, f"RSA must use a modulus >= {min_modulus_bits} bits"

def check_sp800_56c_onestep(name, hashes):
    if name.startswith("SP800_56C_OneStep-HMAC"):
        return check_hash(name, "SP800_56C_OneStep-HMAC", hashes)
    return check_hash(name, "SP800_56C_OneStep", hashes)

def check_sp800_56c_twostep(name, aes_bits, hashes):
    modes = ("CounterKDF", "FeedbackKDF", "DoublePipelineKDF")
    for mode in modes:
        if name.startswith(f"SP800_56C_TwoStep_{mode}-AES"):
            return check_aes(name, f"SP800_56C_TwoStep_{mode}-AES", aes_bits, ("CMAC",))
        if name.startswith(f"SP800_56C_TwoStep_{mode}-HMAC"):
            return check_hash(name, f"SP800_56C_TwoStep_{mode}-HMAC", hashes)
    return False, f"SP 800-56C TwoStep must use a mode in {modes}"

def check_cnsa1_0(component, curves, standalone_hashes, prf_hashes):
    name = component["name"]
    crypto_functions = component.get("cryptoProperties", dict()).get("algorithmProperties", dict()).get("cryptoFunctions", [])

    if name.startswith("ECDH-"):
        return check_curve(name, "ECDH", curves)

    if name.startswith("ECDHE-"):
        return check_curve(name, "ECDHE", curves)

    if name.startswith("ECDSA-"):
        return check_ecdsa(name, curves, standalone_hashes)

    if name.startswith("FFDH-") or name.startswith("FFDHE-"):
        return check_ffdh(name, CNSA1_0_GROUPS)

    if name.startswith("RSA-OAEP-"):
        return check_oaep(name, standalone_hashes, ("MGF1",), CNSA1_0_MIN_MODULUS)

    if name.startswith("RSA-X9.31-"):
        return False, f"RSA with X9.31 padding is not defined"

    if name.startswith("RSA-PKCS1-1.5-"):
        if "encrypt" in crypto_functions or "decrypt" in crypto_functions:
            return False, f"RSA encryption / decryption with PKCS#1 v1.5 padding is not defined"

        for hash in standalone_hashes:
            if name.startswith(f"RSA-PKCS1-1.5-{hash}"):
                match = re.fullmatch(fr"RSA-PKCS1-1.5-{hash}-(\d+)", name)
                if match and int(match.group(1)) >= CNSA1_0_MIN_MODULUS:
                    return True, None
                return False, f"RSA-PKCS1-1.5 must use a modulus >= {CNSA1_0_MIN_MODULUS} bits"
        return False, f"RSA-PKCS1-1.5 must use a hash in {standalone_hashes}"

    if name.startswith("RSA-PSS-"):
        return check_pss(name, standalone_hashes, ("MGF1",), CNSA1_0_MIN_MODULUS)

    if name.startswith("RSA-"):
        return check_rsa(name, CNSA1_0_MIN_MODULUS)

    return check_cnsa2_0(component, standalone_hashes, prf_hashes)

def check_cnsa2_0(component, standalone_hashes, prf_hashes):
    name = component["name"]

    if name.startswith("AES-"):
        return name == "AES-256" or name.startswith("AES-256-"), "AES must use 256-bit keys"

    if name.startswith("ANSI-KDF-X9.42-"):
        return check_hash(name, "ANSI-KDF-X9.42", prf_hashes)

    if name.startswith("ANSI-KDF-X9.63-"):
        return check_hash(name, "ANSI-KDF-X9.63", prf_hashes)

    if name.startswith("CMAC-AES-"):
        return name == "CMAC-AES-256", "AES must use 256-bit keys"

    if name.startswith("CTR_DRBG-AES-"):
        return name == "CTR_DRBG-AES-256", "AES must use 256-bit keys"

    if name.startswith("Hash_DRBG-"):
        return check_hash(name, "Hash_DRBG", prf_hashes)

    if name.startswith("HKDF-"):
        return check_hash(name, "HKDF", prf_hashes)

    if name.startswith("HMAC-"):
        return check_hash(name, "HMAC", standalone_hashes)

    if name.startswith("HMAC_DRBG-"):
        return check_hash(name, "HMAC_DRBG", prf_hashes)

    if name == "LMS" or name.startswith("LMS_"):
        return True, None

    if name.startswith("ML-DSA-"):
        return name == "ML-DSA-87", "ML-DSA must use ML-DSA-87"

    if name.startswith("ML-KEM-"):
        return name == "ML-KEM-1024", "ML-KEM must use ML-KEM-1024"

    if name.startswith("PBKDF2-"):
        return check_hash(name, "PBKDF2", prf_hashes)

    for hash in standalone_hashes:
        if name == hash:
            return True, None

    if name.startswith("SP800_108_"):
        modes = ("CounterKDF", "FeedbackKDF", "DoublePipelineKDF")
        for mode in modes:
            if name.startswith(f"SP800_108_{mode}-AES"):
                return name.startswith(f"SP800_108_{mode}-AES-256-CMAC"), "AES must use 256-bit keys"
            if name.startswith(f"SP800_108_{mode}-HMAC"):
                return check_hash(name, f"SP800_108_{mode}-HMAC", prf_hashes)
        return False, f"SP 800-108 must use a mode in {modes}"

    if name.startswith("SP800_56C_OneStep"):
        return check_sp800_56c_onestep(name, prf_hashes)

    if name.startswith("SP800_56C_TwoStep_"):
        return check_sp800_56c_twostep(name, ("256",), prf_hashes)

    if name.startswith("SSH-KDF-"):
        return check_hash(name, "SSH-KDF", prf_hashes)

    if name.startswith("TLS12-PRF-RFC7627-"):
        return check_hash(name, "TLS12-PRF-RFC7627", prf_hashes)

    if name.startswith("TLS13-PRF-"):
        return check_hash(name, "TLS13-PRF", prf_hashes)

    if name.startswith("XMSS-"):
        return True, None

    return False, f"{name} is not included"

def check_enisa2_0(component, aes_bits, hashes):
    name = component["name"]

    if name.startswith("DSA-"):
        match = re.fullmatch(rf"(DSA-\((\d+), (\d+)\))(-.+)?", name)
        if match and int(match.group(2)) >= ENISA2_0_MIN_MODULUS and int(match.group(3)) >= 250:
            if match.group(4) is None:
                return True, None
            return check_hash(name, match.group(1), hashes)

        return False, f"DSA must use log(p, 2) >= {ENISA2_0_MIN_MODULUS} and log(q, 2) >= 250"

    if name.startswith("ECDH-"):
        return check_curve(name, "ECDH", ENISA2_0_CURVES)

    if name.startswith("ECDHE-"):
        return check_curve(name, "ECDHE", ENISA2_0_CURVES)

    if name.startswith("ECDSA-"):
        return check_ecdsa(name, ENISA2_0_CURVES, hashes)

    if name.startswith("ECIES-"):
        return check_curve(name, "ECIES", ENISA2_0_CURVES)

    if name.startswith("FFDH-") or name.startswith("FFDHE-"):
        return check_ffdh(name, ENISA2_0_GROUPS)

    if name == "KMAC128" or name == "KMACXOF128":
        return True, None

    if name.startswith("RSA-OAEP-"):
        return check_oaep(name, hashes, ("MGF1",), ENISA2_0_MIN_MODULUS)

    if name.startswith("RSA-X9.31-"):
        return False, f"RSA with X9.31 padding is not recommended"

    if name.startswith("RSA-PKCS1-1.5-"):
        return False, f"RSA with PKCS#1 v1.5 padding is not recommended"

    if name.startswith("RSA-PSS-"):
        return check_pss(name, hashes, ("MGF1",), ENISA2_0_MIN_MODULUS)

    if name.startswith("RSA-"):
        return check_rsa(name, ENISA2_0_MIN_MODULUS)

    return check_enisa2_0_pqc(component, aes_bits, hashes)

def check_enisa2_0_pqc(component, aes_bits, hashes):

CHECKERS = {
    "cnsa1.0": ("CNSA 1.0",
        lambda component: check_cnsa1_0(component,
                                        ("P-384",),
                                        ("SHA-384",),
                                        ("SHA-384",))
    ),
    "pl005-add2": ("NIAP Policy Letter #5 Addendum 2",
        lambda component: check_cnsa1_0(component,
                                        ("P-384", "P-521"),
                                        ("SHA-384", "SHA-512", "SHA3-384", "SHA3-512"),
                                        ("SHA-384", "SHA-512"))
    ),
    "cnsa2.0": ("CNSA 2.0",
        lambda component: check_cnsa2_0(component,
                                        ("SHA-384", "SHA-512", "SHA3-384", "SHA3-512"),
                                        ("SHA-384", "SHA-512"))
    ),
    "cnsa2.0-strict": ("CNSA 2.0 strict (no SHA-3)",
        lambda component: check_cnsa2_0(component,
                                        ("SHA-384", "SHA-512"),
                                        ("SHA-384", "SHA-512"))
    ),
    "enisa2.0": ("Agreed Cryptographic Mechanisms Version 2.0",
        lambda component: check_enisa2_0(component,
                                         ("128", "192", "256"),
                                         ("SHA-256", "SHA-384", "SHA-512", "SHA-512/256", "SHA3-256", "SHA3-384", "SHA3-512"))
    ),
    "enisa2.0-pqc": ("(post-quantum) Agreed Cryptographic Mechanisms Version 2.0",
        lambda component: check_enisa2_0_pqc(component,
                                             ("192", "256"),
                                             ("SHA-384", "SHA-512", "SHA3-384", "SHA3-512"))
    ),
}

def main():
    parser = argparse.ArgumentParser(description="Check compliance of a CycloneDX 1.7 CBOM against standards")
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-s", "--standard", choices=CHECKERS.keys(), required=True)
    args = parser.parse_args()

    with open(args.input) as f:
        bom = json.load(f)

    has_ecdh, has_ffdh = False, False
    has_sig = False
    has_ml_kem_1024 = False
    has_ml_dsa_87, has_lms, has_xmss = False, False, False

    standard, checker = CHECKERS[args.standard]
    for component in bom["components"]:
        if component["type"] != "cryptographic-asset":
            continue

        name = component["name"]
        result, reason = checker(component)
        if not result:
            print(f"{name} is not compliant to {standard}: {reason}")

        crypto_functions = component.get("cryptoProperties", dict()).get("algorithmProperties", dict()).get("cryptoFunctions", [])
        is_sig = "sign" in crypto_functions or "verify" in crypto_functions
        is_kem = "encapsulate" in crypto_functions or "decapsulate" in crypto_functions
        has_ecdh |= name.startswith("ECDH")
        has_ffdh |= name.startswith("FFDH")
        has_sig |= is_sig
        has_ml_kem_1024 |= name == "ML-KEM-1024" and is_kem
        has_ml_dsa_87 |= name == "ML-DSA-87" and is_sig
        has_lms |= (name == "LMS" or name.startswith("LMS_")) and is_sig
        has_xmss |= name.startswith("XMSS-") and is_sig

    print("")
    if has_ml_kem_1024:
        print("BOM is CNSA 2.0 (KEM) ready: ML-KEM-1024 present")
    elif has_ecdh or has_ffdh:
        print("BOM is not CNSA 2.0 (KEM) ready: ECDH / FFDH present but ML-KEM-1024 not present")

    if has_ml_dsa_87:
        print("BOM is CNSA 2.0 (SIG) ready: ML-DSA-87 present")
    elif has_lms:
        print("BOM is CNSA 2.0 (SIG) ready: LMS present")
    elif has_xmss:
        print("BOM is CNSA 2.0 (SIG) ready: XMSS present")
    elif has_sig:
        print("BOM is not CNSA 2.0 (SIG) ready: signatures present but ML-DSA-87 / LMS / XMSS not present")

if __name__ == "__main__":
    main()
