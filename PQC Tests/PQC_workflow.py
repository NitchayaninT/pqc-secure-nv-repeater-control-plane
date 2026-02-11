#from kyber_py.kyber import Kyber768
import oqs 
from oqs import KeyEncapsulation, get_enabled_kem_mechanisms
from time import perf_counter_ns

kem_name = "ML-KEM-768" # For Kyber768

def time_once(fn, *args, **kwargs):
    t0 = time.perf_counter_ns()
    out = fn(*args, **kwargs)
    t1 = time.perf_counter_ns()
    return out, (t1 - t0) / 1e6  # ms

def ms(dt_ns): 
    return dt_ns / 1e6

with oqs.KeyEncapsulation(kem_name) as kem:
    # Keygen
    t0 = perf_counter_ns()
    pk = kem.generate_keypair()
    t1 = perf_counter_ns()
    sk_internal = kem.export_secret_key()  # keep if you want sizes
    print(f"keygen: {ms(t1-t0):.3f} ms | pk={len(pk)} bytes | sk={len(sk_internal)} bytes")

    # Encaps
    t0 = perf_counter_ns()
    ct, ss_enc = kem.encap_secret(pk)
    t1 = perf_counter_ns()
    print(f"encaps: {ms(t1-t0):.3f} ms | ct={len(ct)} bytes | ss={len(ss_enc)} bytes")

    # Decaps
    t0 = perf_counter_ns()
    ss_dec = kem.decap_secret(ct)
    t1 = perf_counter_ns()
    print(f"decaps: {ms(t1-t0):.3f} ms")

    print("shared secret match:", ss_enc == ss_dec)

## Note : Key Gen time > Encaps > Decaps