import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("benchmark_raw.csv")

operation = "decrypt"   # đổi thành "encrypt" nếu muốn vẽ mã hóa
target_size = "1 KB"  # Chọn kích thước muốn vẽ: "1 KB", "4 KB", "16 KB", "256 KB", "1 MB", "8 MB"

df = df[df["operation"] == operation]
df = df[df["size_label"] == target_size]

plt.figure(figsize=(12, 6))

for mode in df["mode"].unique():
    d = df[df["mode"] == mode]
    plt.plot(d["run_index"], d["time_s"], label=mode.upper())

plt.title(f"Thời gian thực thi ({operation.capitalize()}): benchmark_{target_size.replace(' ', '')}.bin.csv")
plt.xlabel("Số lần chạy (Run)")
plt.ylabel("Thời gian (Giây)")
plt.grid(True)
plt.legend()
plt.tight_layout()

out_file = f"benchmark_{operation}_{target_size.replace(' ', '')}_plot.png"
plt.savefig(out_file, dpi=300)
plt.show()

print("Saved:", out_file)