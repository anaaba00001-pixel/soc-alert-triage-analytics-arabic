from clean import clean_data
from rules import load_threshold   # or wherever load_threshold lives

_, _, wed = clean_data()
slow = wed[wed["Label"].isin(["DoS slowloris", "DoS Slowhttptest"])]
thr = load_threshold("threshold_tuned.csv")

print("total slow attacks:", len(slow))
print("pass duration >:", (slow["Flow Duration"] > thr[("Flow Duration", 80)]).sum())
print("pass bytes/s   <:", (slow["Flow Bytes/s"]  < thr[("Flow Bytes/s", 80)]).sum())
print("pass IAT max   >:", (slow["Flow IAT Max"]  > thr[("Flow IAT Max", 80)]).sum())
print("pass port 80    :", (slow["Destination Port"] == 80).sum())