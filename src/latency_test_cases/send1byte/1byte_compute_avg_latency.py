def compute_average(filename):
    with open(filename, "r") as f:
        values = [float(line.strip().split(",")[1]) for line in f if line.strip()]
    return sum(values) / len(values)

# compute average latency for PK transmission, CT transmission, and overall latency
avg_pk = compute_average("1byte_pk_latency.txt")
avg_ct = compute_average("1byte_ct_latency.txt")
avg_overall = compute_average("1byte_overall_latency.txt")

# compute average latency for Multi-unicast PK transmission, CT transmission, and overall latency
avg_pk_multiuni = compute_average("1byte_multiuni_pk_latency.txt")
avg_ct_multiuni = compute_average("1byte_multiuni_ct_latency.txt")
avg_overall_multiuni = compute_average("1byte_multiuni_overall_latency.txt")

print("-- 1Byte Unicast Handshake Latency --")
print("Average PK latency:", avg_pk)
print("Average CT latency:", avg_ct)
print("Average overall latency:", avg_overall)

print("\n-- 1Byte Multi-unicast Handshake Latency --")
print("Average PK latency:", avg_pk_multiuni)
print("Average CT latency:", avg_ct_multiuni)
print("Average overall latency:", avg_overall_multiuni)
