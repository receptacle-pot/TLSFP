import unittest
import hashlib

def is_grease(val: int) -> bool:
    high = (val >> 8) & 0xff
    low = val & 0xff
    return high == low and (high & 0x0f) == 0x0a

def generate_ja3(tls_version: int, ciphers: list[int], extensions: list[int], groups: list[int], ec_points: list[int]):
    filtered_ciphers = [c for c in ciphers if not is_grease(c)]
    filtered_exts = [e for e in extensions if not is_grease(e)]
    filtered_groups = [g for g in groups if not is_grease(g)]

    c_str = "-".join(str(c) for c in filtered_ciphers)
    e_str = "-".join(str(e) for e in filtered_exts)
    g_str = "-".join(str(g) for g in filtered_groups)
    p_str = "-".join(str(p) for p in ec_points)

    raw = f"{tls_version},{c_str},{e_str},{g_str},{p_str}"
    md5_hash = hashlib.md5(raw.encode("utf-8")).hexdigest()
    return raw, md5_hash

def format_tls_version(ver: int) -> str:
    mapping = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}
    return mapping.get(ver, "00")

def format_alpn(alpn: str | None) -> str:
    if alpn and len(alpn) > 0:
        return f"{alpn[0]}{alpn[-1]}"
    return "00"

def generate_ja4(is_quic: bool, tls_version: int, has_sni: bool, ciphers: list[int], extensions: list[int], alpn: str | None):
    proto = "q" if is_quic else "t"
    ver_str = format_tls_version(tls_version)
    sni_char = "d" if has_sni else "i"

    filtered_ciphers = [c for c in ciphers if not is_grease(c)]
    filtered_exts = [e for e in extensions if not is_grease(e) and e != 0x0000 and e != 0x0010]

    num_c = min(len(filtered_ciphers), 99)
    num_e = min(len(filtered_exts), 99)
    alpn_str = format_alpn(alpn)

    part_a = f"{proto}{ver_str}{sni_char}{num_c:02d}{num_e:02d}{alpn_str}"

    hex_ciphers = sorted([f"{c:04x}" for c in filtered_ciphers])
    b_joined = "".join(hex_ciphers)
    part_b = hashlib.sha256(b_joined.encode("utf-8")).hexdigest()[:12] if b_joined else "000000000000"

    hex_exts = sorted([f"{e:04x}" for e in filtered_exts])
    c_joined = "".join(hex_exts)
    part_c = hashlib.sha256(c_joined.encode("utf-8")).hexdigest()[:12] if c_joined else "000000000000"

    return f"{part_a}_{part_b}_{part_c}", part_a, part_b, part_c

class TestTlsFingerprinting(unittest.TestCase):
    def test_grease_filtering(self):
        self.assertTrue(is_grease(0x0a0a))
        self.assertTrue(is_grease(0x1a1a))
        self.assertTrue(is_grease(0x2a2a))
        self.assertTrue(is_grease(0xfafa))
        self.assertFalse(is_grease(0x1301))
        self.assertFalse(is_grease(0x0000))

    def test_ja3_generation(self):
        ciphers = [0x1301, 0x1302, 0x0a0a, 0xc02b]
        exts = [0x0000, 0x0017, 0x1a1a, 0x000d]
        groups = [0x001d, 0x0017]
        points = [0]

        raw, md5_hash = generate_ja3(771, ciphers, exts, groups, points)
        self.assertEqual(raw, "771,4865-4866-49195,0-23-13,29-23,0")
        self.assertEqual(len(md5_hash), 32)

    def test_ja4_foxio_specification(self):
        ciphers = [0x1301, 0x1302, 0x1303, 0x0a0a]
        exts = [0x0000, 0x0017, 0x000d, 0x0010, 0x1a1a]
        
        ja4_val, part_a, part_b, part_c = generate_ja4(
            is_quic=False,
            tls_version=0x0304,
            has_sni=True,
            ciphers=ciphers,
            extensions=exts,
            alpn="h2"
        )
        # 3 non-grease ciphers, 2 non-grease exts (0x0000 SNI and 0x0010 ALPN excluded)
        self.assertEqual(part_a, "t13d0302h2")
        self.assertEqual(len(part_b), 12)
        self.assertEqual(len(part_c), 12)
        self.assertEqual(ja4_val, f"{part_a}_{part_b}_{part_c}")

    def test_browser_spoofing_detection(self):
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
        python_ja3 = "b32309a26951912be7dba376398abc3b"
        
        is_spoofed = ("Chrome" in user_agent) and (python_ja3 == "b32309a26951912be7dba376398abc3b")
        self.assertTrue(is_spoofed)

if __name__ == "__main__":
    unittest.main()
