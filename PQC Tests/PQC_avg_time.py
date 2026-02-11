import oqs, time, statistics as st
# average time (mean ms)
kem_name = "ML-KEM-768"
N = 1000 # try 1000 times
W = 30

def bench():
    with oqs.KeyEncapsulation(kem_name) as kem:
        # warmup
        for _ in range(W):
            pk = kem.generate_keypair()
            ct, ss = kem.encap_secret(pk)
            kem.decap_secret(ct)

        keygen_t, enc_t, dec_t = [], [], []

        for _ in range(N):
            # average time to generate key pair (averaged over N runs)
            t0 = time.perf_counter_ns()
            pk = kem.generate_keypair()
            t1 = time.perf_counter_ns()
            sk_internal = kem.export_secret_key() 

            t2 = time.perf_counter_ns()
            ct, ss1 = kem.encap_secret(pk)
            t3 = time.perf_counter_ns()

            t4 = time.perf_counter_ns()
            ss2 = kem.decap_secret(ct)
            t5 = time.perf_counter_ns()

            assert ss1 == ss2

            keygen_t.append((t1-t0)/1e6)
            enc_t.append((t3-t2)/1e6)
            dec_t.append((t5-t4)/1e6)

        def summ(x):
            x_sorted = sorted(x)
             # gets results from statistics lib
            return (st.mean(x), x_sorted[len(x)//2], x_sorted[int(len(x)*0.95)-1])

        print("keygen mean/median/p95 (ms):", summ(keygen_t))
        print("encaps mean/median/p95 (ms):", summ(enc_t))
        print("decaps mean/median/p95 (ms):", summ(dec_t))
        print("pk length :", len(pk))
        print("ct length :", len(ct))
        print("sk length :", len(sk_internal))
        print("ss length :", len(ss))

bench()
