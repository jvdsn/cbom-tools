import argparse
import datetime
import itertools
import json
import re
import requests
import sys
import uuid

SPEC_VERSION = "1.7"
HTML_URL = "https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?source=%s&number=%s"
JSON_URL = "https://csrc.nist.gov/csrcservices/public/cavp/RESTApi/ValidationJSON/%d"


# Returns minimum and maximum for a domain.
def get_domain_min_max(domain):
    if "," in domain:
        # Assume list of elements, get minimum and maximum.
        elements = list(map(lambda element: int(element.strip()), domain.split(",")))
        return min(elements), max(elements)
    if "-" in domain:
        # Assume range, get minimum and maximum.
        min_max = domain.split(" ")[0].split("-")
        return int(min_max[0]), int(min_max[1])
    # Assume just one integer, return both as minimum and maximum.
    return int(domain), int(domain)

# Return normalized name and pre-image security strength (in bits) for a hash algorithm.
def normalize_hash(algorithm):
    match algorithm:
        case "Ascon-Hash256":
            return "Ascon-Hash256", 256
        case "Ascon-CXOF128" | "Ascon-XOF128":
            return algorithm, 128
        case "SHA-1":
            return algorithm, 160
        case "SHA-224" | "SHA2-224":
            return "SHA-224", 224
        case "SHA-256" | "SHA2-256":
            return "SHA-256", 256
        case "SHA-384" | "SHA2-384":
            return "SHA-384", 384
        case "SHA-512" | "SHA2-512":
            return "SHA-512", 512
        case "SHA-512/224" | "SHA2-512/224":
            return "SHA-512/224", 224
        case "SHA-512/256" | "SHA2-512/256":
            return "SHA-512/256", 256
        case "SHA3-224":
            return "SHA3-224", 224
        case "SHA3-256":
            return "SHA3-256", 256
        case "SHA3-384":
            return "SHA3-384", 384
        case "SHA3-512":
            return "SHA3-512", 512
        case "SHAKE128" | "SHAKE-128":
            return "SHAKE128", 128
        case "SHAKE256" | "SHAKE-256":
            return "SHAKE256", 256
        case "cSHAKE128" | "cSHAKE-128":
            return "cSHAKE128", 128
        case "cSHAKE256" | "cSHAKE-256":
            return "cSHAKE256", 256
        case "TupleHash128" | "TupleHashXOF128" | "ParallelHash128" | "ParallelHashXOF128":
            return algorithm, 128
        case "TupleHash256" | "TupleHashXOF256" | "ParallelHash256" | "ParallelHashXOF256":
            return algorithm, 256

    return None

# Return normalized name and security strength (in bits) for a MAC algorithm.
def normalize_mac(algorithm):
    if algorithm.startswith("HMAC-"):
        hash_algorithm, security_bits = normalize_hash(algorithm[5:])
        return f"HMAC-{hash_algorithm}", security_bits

    match algorithm:
        case "CMAC-TDES":
            return "3DES-CMAC", 112
        case "CMAC-AES128":
            return "AES-128-CMAC", 128
        case "CMAC-AES192":
            return "AES-192-CMAC", 192
        case "CMAC-AES256":
            return "AES-256-CMAC", 256
        case "KMAC128" | "KMAC-128":
            return "KMAC128", 128
        case "KMAC256" | "KMAC-256":
            return "KMAC256", 256
        case "KMACXOF128" | "KMACXOF-128":
            return "KMACXOF128", 128
        case "KMACXOF256" | "KMACXOF-256":
            return "KMACXOF256", 256

    return None

# Used for symmetric cryptography, MACs, KDFs, etc.
def add_security_level(security_bits, algorithm_properties):
    algorithm_properties["classicalSecurityLevel"] = security_bits
    if security_bits >= 256:
        algorithm_properties["nistQuantumSecurityLevel"] = 5
    elif security_bits >= 192:
        algorithm_properties["nistQuantumSecurityLevel"] = 3
    elif security_bits >= 128:
        algorithm_properties["nistQuantumSecurityLevel"] = 1
    else:
        algorithm_properties["nistQuantumSecurityLevel"] = 0

# Used for hashes and XOFs.
def add_hash_security_level(security_bits, algorithm_properties):
    algorithm_properties["classicalSecurityLevel"] = security_bits
    if security_bits >= 256:
        algorithm_properties["nistQuantumSecurityLevel"] = 6
    elif security_bits >= 192:
        algorithm_properties["nistQuantumSecurityLevel"] = 4
    elif security_bits >= 128:
        algorithm_properties["nistQuantumSecurityLevel"] = 2
    else:
        algorithm_properties["nistQuantumSecurityLevel"] = 0

# Used for DSA and RSA. For RSA, set L = N = modulus.
def add_dsa_rsa_security_level(L, N, algorithm_properties):
    if L >= 15360 and N >= 512:
        algorithm_properties["classicalSecurityLevel"] = 256
    elif L >= 7680 and N >= 384:
        algorithm_properties["classicalSecurityLevel"] = 192
    elif L >= 3072 and N >= 256:
        algorithm_properties["classicalSecurityLevel"] = 128
    elif L >= 2048 and N >= 224:
        algorithm_properties["classicalSecurityLevel"] = 112
    elif L >= 1024 and N >= 160:
        algorithm_properties["classicalSecurityLevel"] = 80
    else:
        algorithm_properties["classicalSecurityLevel"] = 0
    # Shor's algorithm breaks DSA and RSA.
    algorithm_properties["nistQuantumSecurityLevel"] = 0

# Used for ECC and FFC.
def add_ecc_ffc_security_level(curve_group, algorithm_properties):
    match curve_group:
        case "P-521" | "K-571" | "B-571":
            algorithm_properties["classicalSecurityLevel"] = 256
        case "Ed448":
            algorithm_properties["classicalSecurityLevel"] = 224
        case "P-384" | "K-409" | "B-409":
            algorithm_properties["classicalSecurityLevel"] = 192
        case "ffdhe8192" | "MODP-8192":
            algorithm_properties["classicalSecurityLevel"] = 192
        case "P-256" | "K-283" | "B-283":
            algorithm_properties["classicalSecurityLevel"] = 128
        case "Ed25519":
            algorithm_properties["classicalSecurityLevel"] = 128
        case "ffdhe6144" | "MODP-6144":
            algorithm_properties["classicalSecurityLevel"] = 128
        case "ffdhe4096" | "MODP-4096":
            algorithm_properties["classicalSecurityLevel"] = 128
        case "ffdhe3072" | "MODP-3072":
            algorithm_properties["classicalSecurityLevel"] = 128
        case "P-224" | "K-233" | "B-233":
            algorithm_properties["classicalSecurityLevel"] = 112
        case "ffdhe2048" | "MODP-2048":
            algorithm_properties["classicalSecurityLevel"] = 112
        case "FB" | "FC":
            algorithm_properties["classicalSecurityLevel"] = 112
        case "P-192":
            algorithm_properties["classicalSecurityLevel"] = 96
        case "K-163" | "B-163":
            algorithm_properties["classicalSecurityLevel"] = 80
        case _:
            algorithm_properties["classicalSecurityLevel"] = 0
    # Shor's algorithm breaks ECC and FFC.
    algorithm_properties["nistQuantumSecurityLevel"] = 0

def add_pqc_security_level(parameter_set, algorithm_properties):
    # Classical security levels are not defined for ML-KEM, ML-DSA, and SLH-DSA.
    match parameter_set:
        case "ML-DSA-87" | "ML-KEM-1024":
            algorithm_properties["nistQuantumSecurityLevel"] = 5
        case "SLH-DSA-SHA2-256s" | "SLH-DSA-SHAKE-256s" | "SLH-DSA-SHA2-256f" | "SLH-DSA-SHAKE-256f":
            algorithm_properties["nistQuantumSecurityLevel"] = 5
        case "LMS_SHA256_M32_H5" | "LMS_SHA256_M32_H10" | "LMS_SHA256_M32_H15" | "LMS_SHA256_M32_H20" | "LMS_SHA256_M32_H25":
            algorithm_properties["classicalSecurityLevel"] = 256
            algorithm_properties["nistQuantumSecurityLevel"] = 5
        case "LMOTS_SHA256_M32_H5" | "LMOTS_SHA256_M32_H10" | "LMOTS_SHA256_M32_H15" | "LMOTS_SHA256_M32_H20" | "LMOTS_SHA256_M32_H25":
            algorithm_properties["classicalSecurityLevel"] = 256
            algorithm_properties["nistQuantumSecurityLevel"] = 5
        case "LMS_SHAKE_M32_H5" | "LMS_SHAKE_M32_H10" | "LMS_SHAKE_M32_H15" | "LMS_SHAKE_M32_H20" | "LMS_SHAKE_M32_H25":
            algorithm_properties["classicalSecurityLevel"] = 256
            algorithm_properties["nistQuantumSecurityLevel"] = 5
        case "LMOTS_SHAKE_M32_H5" | "LMOTS_SHAKE_M32_H10" | "LMOTS_SHAKE_M32_H15" | "LMOTS_SHAKE_M32_H20" | "LMOTS_SHAKE_M32_H25":
            algorithm_properties["classicalSecurityLevel"] = 256
            algorithm_properties["nistQuantumSecurityLevel"] = 5
        case "ML-DSA-65" | "ML-KEM-768":
            algorithm_properties["nistQuantumSecurityLevel"] = 3
        case "SLH-DSA-SHA2-192s" | "SLH-DSA-SHAKE-192s" | "SLH-DSA-SHA2-192f" | "SLH-DSA-SHAKE-192f":
            algorithm_properties["nistQuantumSecurityLevel"] = 3
        case "LMS_SHA256_M24_H5" | "LMS_SHA256_M24_H10" | "LMS_SHA256_M24_H15" | "LMS_SHA256_M24_H20" | "LMS_SHA256_M24_H25":
            algorithm_properties["classicalSecurityLevel"] = 192
            algorithm_properties["nistQuantumSecurityLevel"] = 3
        case "LMOTS_SHA256_M24_H5" | "LMOTS_SHA256_M24_H10" | "LMOTS_SHA256_M24_H15" | "LMOTS_SHA256_M24_H20" | "LMOTS_SHA256_M24_H25":
            algorithm_properties["classicalSecurityLevel"] = 192
            algorithm_properties["nistQuantumSecurityLevel"] = 3
        case "LMS_SHAKE_M24_H5" | "LMS_SHAKE_M24_H10" | "LMS_SHAKE_M24_H15" | "LMS_SHAKE_M24_H20" | "LMS_SHAKE_M24_H25":
            algorithm_properties["classicalSecurityLevel"] = 192
            algorithm_properties["nistQuantumSecurityLevel"] = 3
        case "LMOTS_SHAKE_M24_H5" | "LMOTS_SHAKE_M24_H10" | "LMOTS_SHAKE_M24_H15" | "LMOTS_SHAKE_M24_H20" | "LMOTS_SHAKE_M24_H25":
            algorithm_properties["classicalSecurityLevel"] = 192
            algorithm_properties["nistQuantumSecurityLevel"] = 3
        case "ML-DSA-44":
            algorithm_properties["nistQuantumSecurityLevel"] = 2
        case "ML-KEM-512":
            algorithm_properties["nistQuantumSecurityLevel"] = 1
        case "SLH-DSA-SHA2-128s" | "SLH-DSA-SHAKE-128s" | "SLH-DSA-SHA2-128f" | "SLH-DSA-SHAKE-128f":
            algorithm_properties["nistQuantumSecurityLevel"] = 1
        case _:
            algorithm_properties["nistQuantumSecurityLevel"] = 0

def yield_hash(name, family):
    name, output_bits = normalize_hash(name)
    algorithm_properties = dict()
    algorithm_properties["primitive"] = "hash"
    algorithm_properties["algorithmFamily"] = family
    algorithm_properties["parameterSetIdentifier"] = str(output_bits)
    algorithm_properties["cryptoFunctions"] = ["digest"]
    # Use collision security strength as lower bound.
    add_hash_security_level(output_bits // 2, algorithm_properties)
    yield name, algorithm_properties, None

def yield_xof(name, family):
    name, output_bits = normalize_hash(name)
    algorithm_properties = dict()
    algorithm_properties["primitive"] = "xof"
    algorithm_properties["algorithmFamily"] = family
    algorithm_properties["parameterSetIdentifier"] = str(output_bits)
    algorithm_properties["cryptoFunctions"] = ["digest"]
    add_hash_security_level(output_bits, algorithm_properties)
    yield name, algorithm_properties, None

def yield_kdf(name, family, security_bits, dependency):
    algorithm_properties = dict()
    algorithm_properties["primitive"] = "kdf"
    # TODO: not in v1.7
    # algorithm_properties["algorithmFamily"] = family
    algorithm_properties["cryptoFunctions"] = ["keyderive"]
    add_security_level(security_bits, algorithm_properties)
    yield name, algorithm_properties, dependency

def parse_3des(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    for keying_option in capabilities.get("Keying Option", "").split(","):
        keying_option = keying_option.strip()
        algorithm_properties = dict()
        algorithm_properties["primitive"] = primitive
        algorithm_properties["algorithmFamily"] = "3DES"
        algorithm_properties["parameterSetIdentifier"] = keying_option

        # TODO: update for v2.0
        if subfamily in ["CBC", "ECB", "CCM", "GCM", "CFB", "OFB", "CTR"]:
            algorithm_properties["mode"] = subfamily.lower()
        else:
            algorithm_properties["mode"] = "other"

        algorithm_properties["cryptoFunctions"] = []
        if primitive == "mac":
            algorithm_properties["cryptoFunctions"].append("tag")
        else:
            direction = capabilities.get("Direction", "Encrypt, Decrypt")
            if "Encrypt" in direction:
                algorithm_properties["cryptoFunctions"].append("encrypt")
            if "Decrypt" in direction:
                algorithm_properties["cryptoFunctions"].append("decrypt")

        match keying_option:
            case "1":
                add_security_level(112, algorithm_properties)
                name = f"3DES-192-{subfamily}"
            case "2":
                add_security_level(80, algorithm_properties)
                name = f"3DES-128-{subfamily}"
            case _:
                add_security_level(0, algorithm_properties)
                name = f"3DES-{subfamily}"

        yield name, algorithm_properties, None

def parse_3des_cmac(j, subfamily, primitive):
    for caps_j in j["Capabilities"]["Capabilities"]:
        yield from parse_3des(caps_j, subfamily, primitive)

def parse_aes(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    for key_bits in capabilities["Key Length"].split(","):
        key_bits = key_bits.strip()
        algorithm_properties = dict()
        algorithm_properties["primitive"] = primitive
        algorithm_properties["algorithmFamily"] = "AES"
        algorithm_properties["parameterSetIdentifier"] = key_bits

        # TODO: update for v2.0
        if subfamily in ["CBC", "ECB", "CCM", "GCM", "CFB", "OFB", "CTR"]:
            algorithm_properties["mode"] = subfamily.lower()
        else:
            algorithm_properties["mode"] = "other"

        algorithm_properties["cryptoFunctions"] = []
        if primitive == "mac":
            algorithm_properties["cryptoFunctions"].append("tag")
        else:
            direction = capabilities.get("Direction", "Encrypt, Decrypt")
            if "Encrypt" in direction:
                algorithm_properties["cryptoFunctions"].append("encrypt")
            if "Decrypt" in direction:
                algorithm_properties["cryptoFunctions"].append("decrypt")

        add_security_level(int(key_bits), algorithm_properties)

        if subfamily in ["CCM", "GCM"]:
            for tag_length in capabilities["Tag Length"].split(","):
                tag_length = tag_length.strip()
                yield f"AES-{key_bits}-{subfamily}-{tag_length}", dict(algorithm_properties), None
        else:
            yield f"AES-{key_bits}-{subfamily}", algorithm_properties, None

def parse_aes_cmac(j, subfamily, primitive):
    for caps_j in j["Capabilities"]["Capabilities"]:
        yield from parse_aes(caps_j, subfamily, primitive)

def parse_ansi_kdf(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    for hash_algorithm in capabilities["Hash Algorithm"].split(","):
        hash_algorithm, hash_output_bits = normalize_hash(hash_algorithm.strip())
        yield from yield_kdf(f"ANSI-KDF-{subfamily}-{hash_algorithm}", "ANSI-KDF", hash_output_bits, hash_algorithm)

def parse_ascon(j, subfamily, primitive):
    name = f"Ascon-{subfamily}"
    capabilities = j["Capabilities"]
    if primitive == "ae":
        algorithm_properties = dict()
        algorithm_properties["primitive"] = "ae"
        algorithm_properties["algorithmFamily"] = "Ascon"
        algorithm_properties["parameterSetIdentifier"] = "128"
        algorithm_properties["cryptoFunctions"] = []
        direction = capabilities.get("Direction", "Encrypt, Decrypt")
        if "Encrypt" in direction:
            algorithm_properties["cryptoFunctions"].append("encrypt")
        if "Decrypt" in direction:
            algorithm_properties["cryptoFunctions"].append("decrypt")
        add_security_level(128, algorithm_properties)
        yield name, algorithm_properties, None
    if primitive == "hash":
        yield from yield_hash(name, "Ascon")
    if primitive == "xof":
        yield from yield_xof(name, "Ascon")

def parse_drbg(j, subfamily, primitive):
    for caps_j in j["Capabilities"]["Capabilities"]:
        capabilities = caps_j["Capabilities"]
        mode = capabilities["Mode"]
        match mode:
            case "TDES":
                security_bits = 112
            case "AES-128":
                security_bits = 128
            case "AES-192":
                security_bits = 192
            case "AES-256":
                security_bits = 256
            case _:
                mode, security_bits = normalize_hash(mode)
        algorithm_properties = dict()
        algorithm_properties["primitive"] = "drbg"
        # TODO: not in v1.7
        # algorithm_properties["algorithmFamily"] = subfamily
        algorithm_properties["parameterSetIdentifier"] = mode
        algorithm_properties["cryptoFunctions"] = ["generate"]
        add_security_level(security_bits, algorithm_properties)
        yield f"{subfamily}-{mode}", algorithm_properties, None

def parse_dsa(j, subfamily, primitive):
    for caps_j in j["Capabilities"]["Capabilities"]:
        capabilities = caps_j["Capabilities"]
        L = int(capabilities["L"])
        N = int(capabilities["N"])
        algorithm_properties = dict()
        algorithm_properties["primitive"] = "signature"
        algorithm_properties["algorithmFamily"] = "DSA"
        algorithm_properties["parameterSetIdentifier"] = f"({L}, {N})"
        algorithm_properties["cryptoFunctions"] = [subfamily]
        add_dsa_rsa_security_level(L, N, algorithm_properties)
        if "Hash Algorithm" in capabilities:
            for hash_algorithm in capabilities["Hash Algorithm"].split(","):
                hash_algorithm, _ = normalize_hash(hash_algorithm.strip())
                yield f"DSA-({L}, {N})-{hash_algorithm}", dict(algorithm_properties), hash_algorithm
        else:
            yield f"DSA-({L}, {N})", algorithm_properties, None

def parse_ecdh_mqv(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    if "Curve" in capabilities:
        for curve in capabilities["Curve"].split(","):
            curve = curve.strip()
            algorithm_properties = dict()
            algorithm_properties["primitive"] = "key-agree"
            algorithm_properties["algorithmFamily"] = "ECDH"
            algorithm_properties["parameterSetIdentifier"] = curve
            algorithm_properties["ellipticCurve"] = f"nist/{curve}"
            algorithm_properties["cryptoFunctions"] = [subfamily]
            add_ecc_ffc_security_level(curve, algorithm_properties)
            yield f"ECDHE-{curve}", algorithm_properties, None
    else:
        for curve in capabilities["Domain Parameter Generation Methods"].split(","):
            curve = curve.strip()
            for scheme, scheme_caps in capabilities["Scheme"].items():
                algorithm_properties = dict()
                algorithm_properties["primitive"] = "key-agree"
                if scheme in ["fullMqv", "onePassMqv"]:
                    algorithm_properties["algorithmFamily"] = "MQV"
                    name = f"ECMQV-{curve}"
                elif scheme in ["staticUnified"]:
                    algorithm_properties["algorithmFamily"] = "ECDH"
                    name = f"ECDH-{curve}"
                else:
                    algorithm_properties["algorithmFamily"] = "ECDH"
                    name = f"ECDHE-{curve}"
                algorithm_properties["parameterSetIdentifier"] = curve
                algorithm_properties["ellipticCurve"] = f"nist/{curve}"
                algorithm_properties["cryptoFunctions"] = [subfamily]
                if "Key Pair Generation" in capabilities.get("Function", ""):
                    algorithm_properties["cryptoFunctions"].append("keygen")
                add_ecc_ffc_security_level(curve, algorithm_properties)
                yield name, algorithm_properties, None

def parse_ecdsa(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    for curve in capabilities["Curve"].split(","):
        curve = curve.strip()
        algorithm_properties = dict()
        algorithm_properties["primitive"] = "signature"
        algorithm_properties["algorithmFamily"] = "ECDSA"
        algorithm_properties["parameterSetIdentifier"] = curve
        algorithm_properties["ellipticCurve"] = f"nist/{curve}"
        algorithm_properties["cryptoFunctions"] = [subfamily]
        add_ecc_ffc_security_level(curve, algorithm_properties)
        if "Hash Algorithm" in capabilities:
            for hash_algorithm in capabilities["Hash Algorithm"].split(","):
                hash_algorithm, _ = normalize_hash(hash_algorithm.strip())
                yield f"ECDSA-{curve}-{hash_algorithm}", dict(algorithm_properties), hash_algorithm
        else:
            yield f"ECDSA-{curve}", algorithm_properties, None

def parse_ecdsa_sig(j, subfamily, primitive):
    for caps_j in j["Capabilities"]["Capabilities"]:
        yield from parse_ecdsa(caps_j, subfamily, primitive)

def parse_eddsa(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    for curve in capabilities["Curve"].split(","):
        curve = curve.strip()
        if curve == "ED-25519":
            curve = "Ed25519"
        if curve == "ED-448":
            curve = "Ed448"
        algorithm_properties = dict()
        algorithm_properties["primitive"] = "signature"
        algorithm_properties["algorithmFamily"] = "EdDSA"
        algorithm_properties["parameterSetIdentifier"] = curve
        algorithm_properties["ellipticCurve"] = f"other/{curve}"
        algorithm_properties["cryptoFunctions"] = [subfamily]
        add_ecc_ffc_security_level(curve, algorithm_properties)
        if capabilities.get("Pure", "Yes") == "Yes":
            yield f"{curve}", dict(algorithm_properties), None
        if capabilities.get("PreHash", "No") == "Yes":
            yield f"{curve}ph", dict(algorithm_properties), None

def parse_ffdh_mqv(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    if "Safe Prime Groups" in capabilities:
        for group in capabilities["Safe Prime Groups"].split(","):
            group = group.strip()
            algorithm_properties = dict()
            algorithm_properties["primitive"] = "key-agree"
            algorithm_properties["algorithmFamily"] = "FFDH"
            algorithm_properties["parameterSetIdentifier"] = group
            algorithm_properties["cryptoFunctions"] = [subfamily]
            add_ecc_ffc_security_level(group, algorithm_properties)
            yield f"FFDHE-{group}", algorithm_properties, None
    else:
        for group in capabilities["Domain Parameter Generation Methods"].split(","):
            group = group.strip()
            for scheme, scheme_caps in capabilities["Scheme"].items():
                algorithm_properties = dict()
                algorithm_properties["primitive"] = "key-agree"
                if scheme in ["mqv2", "mqv1"]:
                    algorithm_properties["algorithmFamily"] = "MQV"
                    name = f"FFMQV-{group}"
                elif scheme in ["dhStatic"]:
                    algorithm_properties["algorithmFamily"] = "FFDH"
                    name = f"FFDH-{group}"
                else:
                    algorithm_properties["algorithmFamily"] = "FFDH"
                    name = f"FFDHE-{group}"
                algorithm_properties["parameterSetIdentifier"] = group
                algorithm_properties["cryptoFunctions"] = [subfamily]
                if "Key Pair Generation" in capabilities.get("Function", ""):
                    algorithm_properties["cryptoFunctions"].append("keygen")
                add_ecc_ffc_security_level(group, algorithm_properties)
                yield name, algorithm_properties, None

def parse_hkdf(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    input_bits = get_domain_min_max(capabilities["Shared Secret Length"])
    output_bits = get_domain_min_max(capabilities["Derived Key Length"])
    for hash_algorithm in capabilities["HMAC Algorithm"].split(","):
        hash_algorithm, hash_output_bits = normalize_hash(hash_algorithm.strip())
        yield from yield_kdf(f"HKDF-{hash_algorithm}", "HKDF", hash_output_bits, hash_algorithm)

def parse_hmac(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    hash_algorithm, output_bits = normalize_hash(subfamily)
    algorithm_properties = dict()
    algorithm_properties["primitive"] = "mac"
    algorithm_properties["algorithmFamily"] = "HMAC"
    algorithm_properties["parameterSetIdentifier"] = str(output_bits)
    algorithm_properties["cryptoFunctions"] = ["tag"]
    add_security_level(output_bits, algorithm_properties)
    name = f"HMAC-{hash_algorithm}"
    yield name, algorithm_properties, hash_algorithm

def parse_ike_prf(j, subfamily, primitive):
    for caps_j in j["Capabilities"]["Capabilities"]:
        capabilities = caps_j["Capabilities"]
        for hash_algorithm in capabilities["Hash Algorithm"].split(","):
            hash_algorithm, hash_output_bits = normalize_hash(hash_algorithm.strip())
            # This one should always be implemented, for both IKEv1 and IKEv2.
            yield from yield_kdf(f"IKE_PRF_DERIVE-{hash_algorithm}", "IKE-PRF", hash_output_bits, hash_algorithm)
            if subfamily == "IKEv1":
                yield from yield_kdf(f"IKE1_PRF_DERIVE-{hash_algorithm}", "IKE-PRF", hash_output_bits, hash_algorithm)
            else:
                yield from yield_kdf(f"IKE2_PRF_PLUS_DERIVE-{hash_algorithm}", "IKE-PRF", hash_output_bits, hash_algorithm)

def yield_lms(prefix, name, subfamily):
    algorithm_properties = dict()
    algorithm_properties["primitive"] = "signature"
    algorithm_properties["algorithmFamily"] = "LMS"
    algorithm_properties["parameterSetIdentifier"] = name[len(prefix) + 1:]
    algorithm_properties["cryptoFunctions"] = [subfamily]
    add_pqc_security_level(name, algorithm_properties)
    yield name, algorithm_properties, None

def parse_lms(j, subfamily, primitive):
    if "Capabilities" in j["Capabilities"]:
        capabilities = j["Capabilities"]["Capabilities"]
        for name in capabilities["LMS Modes"].split(","):
            yield from yield_lms("LMS", name.strip(), subfamily)
        for name in capabilities["LMOTS Modes"].split(","):
            yield from yield_lms("LMOTS", name.strip(), subfamily)
    else:
        for caps_j in j["Capabilities"]["Specific Capabilities"]:
            capabilities = caps_j["Specific Capabilities"]
            yield from yield_lms("LMS", capabilities["LMS Modes"].strip(), subfamily)
            yield from yield_lms("LMOTS", capabilities["LMOTS Modes"].strip(), subfamily)

def parse_ml_dsa_(j, prefix, subfamily):
    capabilities = j["Capabilities"]
    for parameter_set in capabilities["Parameter Sets"].split(","):
        parameter_set = parameter_set.strip()
        algorithm_properties = dict()
        algorithm_properties["primitive"] = "signature"
        algorithm_properties["algorithmFamily"] = "ML-DSA"
        algorithm_properties["parameterSetIdentifier"] = parameter_set[7:]
        algorithm_properties["cryptoFunctions"] = [subfamily]
        add_pqc_security_level(parameter_set, algorithm_properties)
        if prefix == "Hash":
            for hash_algorithm in capabilities["Hash Algorithms"].split(","):
                hash_algorithm, _ = normalize_hash(hash_algorithm.strip())
                yield f"{prefix}{parameter_set}-{hash_algorithm}", dict(algorithm_properties), hash_algorithm
        else:
            yield parameter_set, algorithm_properties, None

def parse_ml_dsa(j, subfamily, primitive):
    if "Signature Interfaces" in j["Capabilities"]:
        if "external" in j["Capabilities"]["Signature Interfaces"]:
            pre_hash = j["Capabilities"]["Pre Hash"]
            if "pure" in pre_hash:
                for caps_j in j["Capabilities"]["Capabilities"]:
                    yield from parse_ml_dsa_(caps_j, "", subfamily)
            if "preHash" in pre_hash:
                for caps_j in j["Capabilities"]["Capabilities"]:
                    yield from parse_ml_dsa_(caps_j, "Hash", subfamily)
        if "internal" in j["Capabilities"]["Signature Interfaces"]:
            for caps_j in j["Capabilities"]["Capabilities"]:
                yield from parse_ml_dsa_(caps_j, "", subfamily)
    else:
        yield from parse_ml_dsa_(j, "", subfamily)

def parse_ml_kem(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    for parameter_set in capabilities["Parameter Sets"].split(","):
        parameter_set = parameter_set.strip()
        algorithm_properties = dict()
        algorithm_properties["primitive"] = "kem"
        algorithm_properties["algorithmFamily"] = "ML-KEM"
        algorithm_properties["parameterSetIdentifier"] = parameter_set[7:]
        if "Functions" in capabilities:
            functions = capabilities["Functions"]
            algorithm_properties["cryptoFunctions"] = []
            if "Encapsulation" in functions:
                algorithm_properties["cryptoFunctions"].append("encapsulate")
            if "Decapsulation" in functions:
                algorithm_properties["cryptoFunctions"].append("decapsulate")
        else:
            algorithm_properties["cryptoFunctions"] = [subfamily]
        add_pqc_security_level(parameter_set, algorithm_properties)
        yield parameter_set, algorithm_properties, None

def parse_pbkdf2(j, subfamily, primitive):
    for caps_j in j["Capabilities"]["Capabilities"]:
        capabilities = caps_j["Capabilities"]
        iterations_min, iterations_max = get_domain_min_max(capabilities["Iteration Count"])
        output_bits_min, output_bits_max = get_domain_min_max(capabilities["Key Data Length"])
        for hash_algorithm in capabilities["HMAC Algorithm"].split(","):
            hash_algorithm, hash_output_bits = normalize_hash(hash_algorithm.strip())
            yield from yield_kdf(f"PBKDF2-{hash_algorithm}-{iterations_max}-{output_bits_max}", "PBKDF2", hash_output_bits, hash_algorithm)

def parse_rsa(j, subfamily, primitive):
    for caps_j in j["Capabilities"]["Capabilities"]:
        capabilities = caps_j["Capabilities"]
        for properties_j in capabilities["Properties"]:
            properties = properties_j["Properties"]
            modulo = int(properties["Modulo"])
            if "Hash Pair" in properties:
                for hash_pair_j in properties["Hash Pair"]:
                    hash_pair = hash_pair_j["Hash Pair"]
                    hash_algorithm, _ = normalize_hash(hash_pair["Hash Algorithm"])
                    algorithm_properties = dict()
                    algorithm_properties["primitive"] = "signature"
                    signature_type = capabilities["Signature Type"]
                    match signature_type:
                        case "PKCS 1.5" | "pkcs1v1.5":
                            algorithm_properties["algorithmFamily"] = "RSASSA-PKCS1"
                            algorithm_properties["parameterSetIdentifier"] = str(modulo)
                            algorithm_properties["padding"] = "pkcs1v15"
                            name = f"RSA-PKCS1-1.5-{hash_algorithm}-{modulo}"
                        case "PKCSPSS" | "pss":
                            algorithm_properties["algorithmFamily"] = "RSASSA-PSS"
                            algorithm_properties["parameterSetIdentifier"] = str(modulo)
                            algorithm_properties["padding"] = "other"
                            mask_function = properties.get("Mask Function", "mgf1").upper()
                            salt_length = properties.get("Salt Length", "0")
                            name = f"RSA-PSS-{hash_algorithm}-{mask_function}-{salt_length}-{modulo}"
                        case "ANSI X9.31":
                            # TODO: not in v1.7
                            # algorithm_properties["algorithmFamily"] = "RSA-X931"
                            algorithm_properties["parameterSetIdentifier"] = str(modulo)
                            algorithm_properties["padding"] = "other"
                            name = f"RSA-X9.31-{hash_algorithm}-{modulo}"
                        case _:
                            algorithm_properties["parameterSetIdentifier"] = str(modulo)
                            algorithm_properties["padding"] = "unknown"
                            name = f"RSA-{modulo}"
                    algorithm_properties["cryptoFunctions"] = [subfamily]
                    add_dsa_rsa_security_level(modulo, modulo, algorithm_properties)
                    yield name, algorithm_properties, hash_algorithm
            else:
                algorithm_properties = dict()
                algorithm_properties["primitive"] = primitive
                algorithm_properties["parameterSetIdentifier"] = str(modulo)
                algorithm_properties["cryptoFunctions"] = [subfamily]
                add_dsa_rsa_security_level(modulo, modulo, algorithm_properties)
                yield f"RSA-{modulo}", algorithm_properties, None

def parse_rsa_oaep(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    for modulo in capabilities["Modulo"].split(","):
        modulo = int(modulo.strip())
        for scheme, scheme_caps in capabilities["Scheme"].items():
            kas_role = scheme_caps["KAS Role"]
            for hash_algorithm in scheme_caps["Key Transport Method"]["Hash Algorithms"].split(","):
                hash_algorithm, _ = normalize_hash(hash_algorithm.strip())
                algorithm_properties = dict()
                algorithm_properties["primitive"] = "pke"
                algorithm_properties["algorithmFamily"] = "RSAES-OAEP"
                algorithm_properties["parameterSetIdentifier"] = str(modulo)
                algorithm_properties["padding"] = "oaep"
                algorithm_properties["cryptoFunctions"] = []
                if "initiator" in kas_role:
                    algorithm_properties["cryptoFunctions"].append("encrypt")
                if "responder" in kas_role:
                    algorithm_properties["cryptoFunctions"].append("decrypt")
                if "keyPairGen" in capabilities.get("Function", ""):
                    algorithm_properties["cryptoFunctions"].append("keygen")
                add_dsa_rsa_security_level(modulo, modulo, algorithm_properties)
                yield f"RSA-OAEP-{hash_algorithm}-MGF1-{modulo}", algorithm_properties, hash_algorithm

def parse_sha_1(j, subfamily, primitive):
    yield from yield_hash(subfamily, "SHA-1")

def parse_sha_2(j, subfamily, primitive):
    yield from yield_hash(subfamily, "SHA-2")

def parse_sha_3(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    # SHA-3 functions that are always hashes (SHA3-224, SHA3-256, SHA3-384, SHA3-512).
    if primitive == "hash":
        yield from yield_hash(subfamily, "SHA-3")
    # SHA-3 functions that are always XOFs (SHAKE, cSHAKE).
    if primitive == "xof":
        yield from yield_xof(subfamily, "SHA-3")
    # SHA-3 functions that are MACs, but can also be XOF MACs.
    if primitive == "mac":
        kmac_algorithm, output_bits = normalize_mac(subfamily)
        supports_xof = capabilities["Supports eXtendable-Output Functions"]
        algorithm_properties = dict()
        algorithm_properties["primitive"] = "mac"
        algorithm_properties["algorithmFamily"] = "SHA-3"
        algorithm_properties["parameterSetIdentifier"] = str(output_bits)
        algorithm_properties["cryptoFunctions"] = ["tag"]
        add_security_level(output_bits, algorithm_properties)
        if "No" in supports_xof:
            yield kmac_algorithm, dict(algorithm_properties), None
        if "Yes" in supports_xof:
            yield f"{kmac_algorithm[:-3]}XOF{kmac_algorithm[-3:]}", dict(algorithm_properties), None
    # SHA-3 functions that are either hashes or XOFs (ParallelHash, TupleHash).
    if primitive is None:
        supports_xof = capabilities["Supports eXtendable-Output Functions"]
        if "No" in supports_xof:
            yield from yield_hash(subfamily, "SHA-3")
        if "Yes" in supports_xof:
            yield from yield_xof(f"{subfamily[:-3]}XOF{subfamily[-3:]}", "SHA-3")

def parse_slh_dsa_(j, prefix, subfamily):
    capabilities = j["Capabilities"]
    for parameter_set in capabilities["Parameter Sets"].split(","):
        parameter_set = parameter_set.strip()
        algorithm_properties = dict()
        algorithm_properties["primitive"] = "signature"
        algorithm_properties["algorithmFamily"] = "SLH-DSA"
        algorithm_properties["parameterSetIdentifier"] = parameter_set[8:]
        algorithm_properties["cryptoFunctions"] = [subfamily]
        add_pqc_security_level(parameter_set, algorithm_properties)
        if prefix == "Hash":
            for hash_algorithm in capabilities["Hash Algorithms"].split(","):
                hash_algorithm, _ = normalize_hash(hash_algorithm.strip())
                yield f"{prefix}{parameter_set}-{hash_algorithm}", dict(algorithm_properties), hash_algorithm
        else:
            yield parameter_set, algorithm_properties, None

def parse_slh_dsa(j, subfamily, primitive):
    if "Signature Interfaces" in j["Capabilities"]:
        if "external" in j["Capabilities"]["Signature Interfaces"]:
            pre_hash = j["Capabilities"]["Pre Hash"]
            if "pure" in pre_hash:
                for caps_j in j["Capabilities"]["Capabilities"]:
                    yield from parse_slh_dsa_(caps_j, "", subfamily)
            if "preHash" in pre_hash:
                for caps_j in j["Capabilities"]["Capabilities"]:
                    yield from parse_slh_dsa_(caps_j, "Hash", subfamily)
        if "internal" in j["Capabilities"]["Signature Interfaces"]:
            for caps_j in j["Capabilities"]["Capabilities"]:
                yield from parse_slh_dsa_(caps_j, "", subfamily)
    else:
        yield from parse_slh_dsa_(j, "", subfamily)

def parse_sp800_108(j, subfamily, primitive):
    if subfamily == "KMAC":
        capabilities = j["Capabilities"]
        output_bits_min, output_bits_max = get_domain_min_max(capabilities["Derived Key Length"])
        for mac_mode in capabilities["MAC Modes"].split(","):
            mac_mode, mac_security_bits = normalize_mac(mac_mode.strip())
            yield from yield_kdf(f"SP800_108_KMAC-{mac_mode}-{output_bits_max}", "SP800-108", mac_security_bits, mac_mode)
    else:
        for caps_j in j["Capabilities"]["Capabilities"]:
            capabilities = caps_j["Capabilities"]
            output_bits_min, output_bits_max = get_domain_min_max(capabilities["Supported Lengths"])
            kdf_mode = capabilities["KDF Mode"]
            for mac_mode in capabilities["MAC Mode"].split(","):
                mac_mode, mac_security_bits = normalize_mac(mac_mode.strip())
                match kdf_mode:
                    case "Counter":
                        name = f"SP800_108_CounterKDF-{mac_mode}-{output_bits_max}"
                    case "Feedback":
                        name = f"SP800_108_FeedbackKDF-{mac_mode}-{output_bits_max}"
                    case "Double Pipeline Iteration":
                        name = f"SP800_108_DoublePipelineKDF-{mac_mode}-{output_bits_max}"

                yield from yield_kdf(name, "SP800-108", mac_security_bits, mac_mode)

def parse_sp800_56c(j, subfamily, primitive):
    if subfamily == "OneStep":
        capabilities = j["Capabilities"]
        output_bits_min, output_bits_max = get_domain_min_max(capabilities["Derived Key Length"])
        for aux_j in capabilities["Auxiliary Function Methods"]:
            aux_function = aux_j["Auxiliary Function Methods"]["Auxiliary Function Name"].strip()
            if (res := normalize_hash(aux_function)) is not None:
                aux_function, aux_function_security_bits = res
            else:
                aux_function, aux_function_security_bits = normalize_mac(aux_function)

            yield from yield_kdf(f"SP800_56C_OneStep-{aux_function}-{output_bits_max}", "SP800-56C", aux_function_security_bits, aux_function)

    if subfamily == "TwoStep":
        output_bits_min, output_bits_max = get_domain_min_max(j["Capabilities"]["Derived Key Length"])
        for caps_j in j["Capabilities"]["Capabilities"]:
            capabilities = caps_j["Capabilities"]
            kdf_mode = capabilities["KDF Mode"]
            for mac_mode in capabilities["MAC Modes"].split(","):
                mac_mode, mac_security_bits = normalize_mac(mac_mode.strip())
                match kdf_mode:
                    case "counter":
                        name = f"SP800_56C_TwoStep_CounterKDF-{mac_mode}-{output_bits_max}"
                    case "feedback":
                        name = f"SP800_56C_TwoStep_FeedbackKDF-{mac_mode}-{output_bits_max}"
                    case "double pipeline iteration":
                        name = f"SP800_56C_TwoStep_DoublePipelineKDF-{mac_mode}-{output_bits_max}"

                yield from yield_kdf(name, "SP800-56C", mac_security_bits, mac_mode)

def parse_ssh_kdf(j, subfamily, primitive):
    capabilities = j["Capabilities"]

    for hash_algorithm in capabilities["Hash Algorithm"].split(","):
        hash_algorithm, hash_output_bits = normalize_hash(hash_algorithm.strip())
        yield from yield_kdf(f"SSH-KDF-{hash_algorithm}", "SSH-KDF", hash_output_bits, hash_algorithm)

def parse_tls_prf(j, subfamily, primitive):
    capabilities = j["Capabilities"]
    if subfamily == "TLS1-PRF":
        for tls_version in capabilities["TLS Version"].split(","):
            tls_version = tls_version.strip()
            if tls_version == "v1.0/1.1":
                yield from yield_kdf(subfamily, "TLS-PRF", 128, None)
            else:
                for hash_algorithm in capabilities["Hash Algorithm"].split(","):
                    hash_algorithm, hash_output_bits = normalize_hash(hash_algorithm.strip())
                    yield from yield_kdf(f"TLS12-PRF-{hash_algorithm}", "TLS-PRF", hash_output_bits, hash_algorithm)

    if subfamily == "TLS12-PRF-RFC7627":
        for hash_algorithm in capabilities["Hash Algorithm"].split(","):
            hash_algorithm, hash_output_bits = normalize_hash(hash_algorithm.strip())
            yield from yield_kdf(f"{subfamily}-{hash_algorithm}", "TLS-PRF", hash_output_bits, hash_algorithm)

    if subfamily == "TLS13-PRF":
        for hash_algorithm in capabilities["HMAC Algorithm"].split(","):
            hash_algorithm, hash_output_bits = normalize_hash(hash_algorithm.strip())
            yield from yield_kdf(f"{subfamily}-{hash_algorithm}", "TLS-PRF", hash_output_bits, hash_algorithm)

# (CAVP algorithm) name | parser function | subfamily | primitive
# The interpretation of subfamily depends on the parser function.
# For example it could be an AES mode, a normalized name, a crypto function, or something else entirely.
ALGORITHMS = {
    "AES-CBC":					(parse_aes,		"CBC",			"block-cipher"),
    "AES-CBC-CS1":				(parse_aes,		"CBC-CS1",		"block-cipher"),
    "AES-CBC-CS2":				(parse_aes,		"CBC-CS2",		"block-cipher"),
    "AES-CBC-CS3":				(parse_aes,		"CBC-CS3",		"block-cipher"),
    "AES-CCM":					(parse_aes,		"CCM",			"ae"),
    "AES-CFB1": 				(parse_aes,		"CFB1",			"block-cipher"),
    "AES-CFB8": 				(parse_aes,		"CFB8",			"block-cipher"),
    "AES-CFB128":				(parse_aes,		"CFB128",		"block-cipher"),
    "AES-CMAC":					(parse_aes_cmac,	"CMAC",			"mac"),
    "AES-CTR":					(parse_aes,		"CTR",			"block-cipher"),
    "AES-ECB":					(parse_aes,		"ECB",			"block-cipher"),
    "AES-FF1":					(parse_aes,		"FF1",			"block-cipher"),
    "AES-FF3":					(parse_aes,		"FF3",			"block-cipher"),
    "AES-GCM":					(parse_aes,		"GCM",			"ae"),
    "AES-GCM-SIV":				(parse_aes,		"GCM-SIV",		"ae"),
    "AES-GMAC":					(parse_aes,		"GMAC",			"mac"),
    "AES-KW":					(parse_aes,		"KW",			"key-wrap"),
    "AES-KWP":					(parse_aes,		"KWP",			"key-wrap"),
    "AES-OFB":					(parse_aes,		"OFB",			"block-cipher"),
    "AES-XPN":					(parse_aes,		"XPN",			"ae"),
    "AES-XTS":					(parse_aes,		"XTS",			"block-cipher"),
    "AES-XTS Testing Revision 2.0":		(parse_aes,		"XTS",			"block-cipher"),
    "Ascon AEAD128":				(parse_ascon,		"AEAD128",		"ae"),
    "Ascon CXOF128":				(parse_ascon,		"CXOF128",		"xof"),
    "Ascon Hash256":				(parse_ascon,		"Hash256",		"hash"),
    "Ascon XOF128":				(parse_ascon,		"XOF128",		"xof"),
    "Counter DRBG":				(parse_drbg,		"CTR_DRBG",		"drbg"),
    "cSHAKE-128":				(parse_sha_3,		"cSHAKE128",		"xof"),
    "cSHAKE-256":				(parse_sha_3,		"cSHAKE256",		"xof"),
    # TODO: not in v1.7
    # "DSA PQGGen (FIPS186-4)":			(parse_dsa,		"paramgen",		"signature"),
    # "DSA PQGVer (FIPS186-4)":			(parse_dsa,		"paramver",		"signature"),
    "DSA KeyGen (FIPS186-4)":			(parse_dsa,		"keygen",		"signature"),
    "DSA SigGen (FIPS186-4)":			(parse_dsa,		"sign",			"signature"),
    "DSA SigVer (FIPS186-4)":			(parse_dsa,		"verify",		"signature"),
    "ECDSA KeyGen (FIPS186-4)":			(parse_ecdsa,		"keygen",		"signature"),
    "ECDSA KeyGen (FIPS186-5)":			(parse_ecdsa,		"keygen",		"signature"),
    # TODO: not in v1.7
    # "ECDSA KeyVer (FIPS186-4)":			(parse_ecdsa,		"keyver",		"signature"),
    # "ECDSA KeyVer (FIPS186-5)":			(parse_ecdsa,		"keyver",		"signature"),
    "ECDSA SigGen (FIPS186-4)":			(parse_ecdsa_sig,	"sign",			"signature"),
    "ECDSA SigGen (FIPS186-5)":			(parse_ecdsa_sig,	"sign",			"signature"),
    "Deterministic ECDSA SigGen (FIPS186-5)":	(parse_ecdsa_sig,	"sign",			"signature"),
    "ECDSA SigVer (FIPS186-4)":			(parse_ecdsa_sig,	"verify",		"signature"),
    "ECDSA SigVer (FIPS186-5)":			(parse_ecdsa_sig,	"verify",		"signature"),
    "EDDSA KeyGen":				(parse_eddsa,		"keygen",		"signature"),
    # TODO: not in v1.7
    # "EDDSA KeyVer":				(parse_eddsa,		"keyver",		"signature"),
    "EDDSA SigGen":				(parse_eddsa,		"sign",			"signature"),
    "EDDSA SigVer":				(parse_eddsa,		"verify",		"signature"),
    "Hash DRBG":				(parse_drbg,		"Hash_DRBG",		"drbg"),
    "HMAC DRBG":				(parse_drbg,		"HMAC_DRBG",		"drbg"),
    "HMAC-SHA-1":				(parse_hmac,		"SHA-1",		"mac"),
    "HMAC-SHA2-224":				(parse_hmac,		"SHA-224",		"mac"),
    "HMAC-SHA2-256":				(parse_hmac,		"SHA-256",		"mac"),
    "HMAC-SHA2-384":				(parse_hmac,		"SHA-384",		"mac"),
    "HMAC-SHA2-512/224":			(parse_hmac,		"SHA-512/224",		"mac"),
    "HMAC-SHA2-512/256":			(parse_hmac,		"SHA-512/256",		"mac"),
    "HMAC-SHA2-512":				(parse_hmac,		"SHA-512",		"mac"),
    "HMAC-SHA3-224":				(parse_hmac,		"SHA3-224",		"mac"),
    "HMAC-SHA3-256":				(parse_hmac,		"SHA3-256",		"mac"),
    "HMAC-SHA3-384":				(parse_hmac,		"SHA3-384",		"mac"),
    "HMAC-SHA3-512":				(parse_hmac,		"SHA3-512",		"mac"),
    "KAS-ECC CDH-Component SP800-56Ar3":	(parse_ecdh_mqv,	"generate",		"key-agree"),
    "KAS-ECC Sp800-56Ar3":			(parse_ecdh_mqv,	"generate",		"key-agree"),
    "KAS-ECC-SSC Sp800-56Ar3":			(parse_ecdh_mqv,	"generate",		"key-agree"),
    "KAS-FFC Sp800-56Ar3":			(parse_ffdh_mqv,	"generate",		"key-agree"),
    "KAS-FFC-SSC Sp800-56Ar3":			(parse_ffdh_mqv,	"generate",		"key-agree"),
    "KDA HKDF Sp800-56Cr1":			(parse_hkdf,		None,			"kdf"),
    "KDA HKDF SP800-56Cr2":			(parse_hkdf,		None,			"kdf"),
    "KDA OneStep Sp800-56Cr1":			(parse_sp800_56c,	"OneStep",		"kdf"),
    "KDA OneStep SP800-56Cr2":			(parse_sp800_56c,	"OneStep",		"kdf"),
    "KDA TwoStep Sp800-56Cr1":			(parse_sp800_56c,	"TwoStep",		"kdf"),
    "KDA TwoStep SP800-56Cr2":			(parse_sp800_56c,	"TwoStep",		"kdf"),
    "KDF ANS 9.42":				(parse_ansi_kdf,	"X9.42",		"kdf"),
    "KDF ANS 9.63":				(parse_ansi_kdf,	"X9.63",		"kdf"),
    "KDF IKEv1":				(parse_ike_prf,		"IKEv1",		"kdf"),
    "KDF IKEv2":				(parse_ike_prf,		"IKEv2",		"kdf"),
    "KDF KMAC Sp800-108r1":			(parse_sp800_108,	"KMAC",			"kdf"),
    "KDF SP800-108":				(parse_sp800_108,	"KBKDF",		"kdf"),
    "KDF SSH":					(parse_ssh_kdf,		None,			"kdf"),
    "KDF TLS":					(parse_tls_prf,		"TLS1-PRF",		"kdf"),
    "KMAC-128":					(parse_sha_3,		"KMAC128",		"mac"),
    "KMAC-256":					(parse_sha_3,		"KMAC256",		"mac"),
    "KTS-IFC":					(parse_rsa_oaep,	None,			"pke"),
    "LMS KeyGen":				(parse_lms,		"keygen",		"signature"),
    "LMS SigGen":				(parse_lms,		"sign",			"signature"),
    "LMS SigVer":				(parse_lms,		"verify",		"signature"),
    "ML-DSA KeyGen":				(parse_ml_dsa,		"keygen",		"signature"),
    "ML-DSA SigGen":				(parse_ml_dsa,		"sign",			"signature"),
    "ML-DSA SigVer":				(parse_ml_dsa,		"verify",		"signature"),
    "ML-KEM KeyGen":				(parse_ml_kem,		"keygen",		"kem"),
    "ML-KEM EncapDecap":			(parse_ml_kem,		None,			"kem"),
    "ParallelHash-128":				(parse_sha_3,		"ParallelHash128",	None),
    "ParallelHash-256":				(parse_sha_3,		"ParallelHash256",	None),
    "PBKDF":					(parse_pbkdf2,		None,			"kdf"),
    "RSA KeyGen (FIPS186-4)":			(parse_rsa,		"keygen",		"signature"),
    "RSA KeyGen (FIPS186-5)":			(parse_rsa,		"keygen",		"signature"),
    "RSA SigGen (FIPS186-4)":			(parse_rsa,		"sign",			"signature"),
    "RSA SigGen (FIPS186-5)":			(parse_rsa,		"sign",			"signature"),
    "RSA SigVer (FIPS186-2)":			(parse_rsa,		"verify",	 	"signature"),
    "RSA SigVer (FIPS186-4)":			(parse_rsa,		"verify",		"signature"),
    "RSA SigVer (FIPS186-5)":			(parse_rsa,		"verify",		"signature"),
    "Safe Primes Key Generation":		(parse_ffdh_mqv,	"keygen",		"key-agree"),
    # TODO: not in v1.7
    # "Safe Primes Key Verification":		(parse_ffdh_mqv,	"keyver",		"key-agree"),
    "SHA-1":					(parse_sha_1,		"SHA-1",		"hash"),
    "SHA2-224":					(parse_sha_2,		"SHA-224",		"hash"),
    "SHA2-256":					(parse_sha_2,		"SHA-256",		"hash"),
    "SHA2-384":					(parse_sha_2,		"SHA-384",		"hash"),
    "SHA2-512":					(parse_sha_2,		"SHA-512",		"hash"),
    "SHA2-512/224":				(parse_sha_2,		"SHA-512/224",		"hash"),
    "SHA2-512/256":				(parse_sha_2,		"SHA-512/256",		"hash"),
    "SHA3-224":					(parse_sha_3,		"SHA3-224",		"hash"),
    "SHA3-256":					(parse_sha_3,		"SHA3-256",		"hash"),
    "SHA3-384":					(parse_sha_3,		"SHA3-384",		"hash"),
    "SHA3-512":					(parse_sha_3,		"SHA3-512",		"hash"),
    "SHAKE-128":				(parse_sha_3,		"SHAKE128",		"xof"),
    "SHAKE-256":				(parse_sha_3,		"SHAKE256",		"xof"),
    "SLH-DSA KeyGen":				(parse_slh_dsa,		"keygen",		"signature"),
    "SLH-DSA SigGen":				(parse_slh_dsa,		"sign",			"signature"),
    "SLH-DSA SigVer":				(parse_slh_dsa,		"verify",		"signature"),
    "TDES-CBC":					(parse_3des,		"CBC",			"block-cipher"),
    "TDES-CBCI":				(parse_3des,		"CBCI",			"block-cipher"),
    "TDES-CFB1":				(parse_3des,		"CFB1",			"block-cipher"),
    "TDES-CFB8":				(parse_3des,		"CFB8",			"block-cipher"),
    "TDES-CFB64":				(parse_3des,		"CFB64",		"block-cipher"),
    "TDES-CFBP1":				(parse_3des,		"CFBP1",		"block-cipher"),
    "TDES-CFBP8":				(parse_3des,		"CFBP8",		"block-cipher"),
    "TDES-CFBP64":				(parse_3des,		"CFBP64",		"block-cipher"),
    "TDES-CMAC":				(parse_3des_cmac,	"CMAC",			"mac"),
    "TDES-CTR":					(parse_3des,		"CTR",			"block-cipher"),
    "TDES-ECB":					(parse_3des,		"ECB",			"block-cipher"),
    "TDES-KW":					(parse_3des,		"Wrap",			"key-wrap"),
    "TDES-OFB":					(parse_3des,		"OFB",			"block-cipher"),
    "TDES-OFBI":				(parse_3des,		"OFBI",			"block-cipher"),
    "TLS v1.2 KDF RFC7627":			(parse_tls_prf,		"TLS12-PRF-RFC7627",	"kdf"),
    "TLS v1.3 KDF":				(parse_tls_prf,		"TLS13-PRF",		"kdf"),
    "TupleHash-128":				(parse_sha_3,		"TupleHash128",		None),
    "TupleHash-256":				(parse_sha_3,		"TupleHash256",		None),
}

def parse_implementation(j):
    component = dict()
    component["name"] = j["Name"]
    component["description"] = j["Description"]
    component["version"] = j["Version"]
    match j["Type"]:
        case "SOFTWARE":
            component["type"] = "application"
        case "HARDWARE":
            component["type"] = "device"
        case "FIRMWARE":
            component["type"] = "firmware"
        case _:
            component["type"] = "data"

    manufacturer = dict()
    if "Organization" in j:
        organization = j["Organization"]
        manufacturer["name"] = organization["Name"]
        if "Url" in organization:
            manufacturer["url"] = [organization["Url"]]

    contacts = []
    for contact_j in j.get("Contacts", []):
        contact = dict()
        contact["name"] = contact_j["Name"]
        for email_address in contact_j.get("EmailAddresses", []):
            contact["email"] = email_address
        for phone_number in contact_j.get("PhoneNumbers", []):
            contact["phone"] = phone_number["Number"]

        contacts.append(contact)

    if len(contacts) > 0:
        manufacturer["contact"] = contacts

    if "Address" in j:
        address = dict()
        if "Country" in j["Address"]:
            address["country"] = j["Address"]["Country"]
        if "Region" in j["Address"]:
            address["region"] = j["Address"]["Region"]
        if "Locality" in j["Address"]:
            address["locality"] = j["Address"]["Locality"]
        if "PostalCode" in j["Address"]:
            address["postalCode"] = j["Address"]["PostalCode"]
        address["streetAddress"] = j["Address"]["Street1"]
        manufacturer["address"] = address

    component["manufacturer"] = manufacturer
    component["supplier"] = manufacturer
    return component

def retrieve_validation_id(certificate):
    certificate = ["".join(g) for k, g in itertools.groupby(certificate, str.isalpha)]
    if len(certificate) != 2:
        return 0

    source = certificate[0]
    number = certificate[1]
    response = requests.get(HTML_URL % (source, number))
    match = re.search(r"details\?validation=(\d+)", response.text)
    if match:
        return int(match.group(1))

    return 0

def main():
    parser = argparse.ArgumentParser(description="Convert a NIST CAVP certificate to a CycloneDX 1.7 CBOM")
    parser.add_argument("-c", "--certificate", type=str, help="The CAVP certificate number (e.g., A1234, DRBG1234)")
    parser.add_argument("-v", "--validation_id", type=int, help="The CAVP validation number (e.g., 31293)")
    parser.add_argument("-o", "--output_file", type=str, default="bom.json")
    args = parser.parse_args()

    if args.certificate:
        validation_id = retrieve_validation_id(args.certificate)
    elif args.validation_id:
        validation_id = args.validation_id
    else:
        validation_id = 0

    if validation_id == 0:
        parser.print_help()
        sys.exit(1)

    # Step 1: get the data from the NIST website.
    response = requests.get(JSON_URL % validation_id)
    validation = response.json()

    bom = dict()
    bom["bomFormat"] = "CycloneDX"
    bom["specVersion"] = SPEC_VERSION
    bom["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    bom["version"] = 1

    metadata = dict()
    metadata["timestamp"] = datetime.datetime.now().isoformat()
    metadata["lifecycles"] = [{"phase": "operations"}]
    metadata["properties"] = [{"name": "validation_id", "value": f"{validation_id}"}]
    metadata["component"] = parse_implementation(validation["Implementation"])
    bom["metadata"] = metadata

    # Step 2: create components.
    bom["components"] = []
    component_dependencies = dict()
    for oe_algorithm in validation["ValidationOEAlgorithms"]:
        algorithm = oe_algorithm["Algorithm"]
        if algorithm not in ALGORITHMS:
            print(f"Unknown algorithm {algorithm}")
            continue

        parse_family, subfamily, primitive = ALGORITHMS[algorithm]
        for name, algorithm_properties, dependency_name in parse_family(oe_algorithm, subfamily, primitive):
            algorithm_properties["certificationLevel"] = ["other"]

            crypto_properties = dict()
            crypto_properties["assetType"] = "algorithm"
            crypto_properties["algorithmProperties"] = algorithm_properties

            component = dict()
            component["type"] = "cryptographic-asset"
            component["bom-ref"] = str(uuid.uuid4())
            component["name"] = name
            component["cryptoProperties"] = crypto_properties

            for component_ in bom["components"]:
                algorithm_properties_ = component_["cryptoProperties"]["algorithmProperties"]
                if component_["name"] == name:
                    algorithm_properties_tmp = {k: v for k, v in algorithm_properties.items() if k != "cryptoFunctions"}
                    algorithm_properties_tmp_ = {k: v for k, v in algorithm_properties_.items() if k != "cryptoFunctions"}
                    if algorithm_properties_tmp_ == algorithm_properties_tmp:
                        # Merge cryptoFunctions together rather than adding a new component.
                        cryptoFunctions = algorithm_properties.get("cryptoFunctions", list())
                        cryptoFunctions_ = algorithm_properties_.get("cryptoFunctions", list())
                        algorithm_properties_["cryptoFunctions"] = list(set(cryptoFunctions + cryptoFunctions_))
                        if dependency_name is not None:
                            component_dependencies.setdefault(component_["bom-ref"], set()).add(dependency_name)
                        break
            else:
                bom["components"].append(component)
                if dependency_name is not None:
                    component_dependencies.setdefault(component["bom-ref"], set()).add(dependency_name)

    # Optional step 3: fill in dependencies.
    bom["dependencies"] = []
    for bom_ref, dependency_names in component_dependencies.items():
        dependency = dict()
        dependency["ref"] = bom_ref
        dependency["dependsOn"] = []
        for dependency_name in dependency_names:
            for candidate in bom["components"]:
                if candidate["name"] == dependency_name:
                    dependency["dependsOn"].append(candidate["bom-ref"])
                    break
            else:
                print(f"Unknown dependency {dependency_name} for {bom_ref}")

        if len(dependency["dependsOn"]) > 0:
            bom["dependencies"].append(dependency)

    # Step 4: write CBOM to file.
    with open(args.output_file, "w") as f:
        json.dump(bom, f, indent=4)

if __name__ == "__main__":
    main()
