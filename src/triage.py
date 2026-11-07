import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

RULES_LIST = [
    "brute_force_rate",
    "dos_flood",
    "dos_low_and_slow"
]

RULES_TARGETS = {
    "brute_force_rate": ["FTP-Patator", "SSH-Patator"],
    "dos_flood": ["DoS Hulk", "DoS GoldenEye"],
    "dos_low_and_slow": ["DoS slowloris", "DoS Slowhttptest"],
}

def load_alert(path="alerts.csv"):
    """_summary_

    Args:
        path (str, optional): _description_. Defaults to "alerts.csv".

    Returns:
        _type_: _description_
    """
    alerts_df = pd.read_csv(path)
    
    return alerts_df

def load_results(results_path="results.csv", attacks_results_path="results_per_attack.csv"):
    """_summary_

    Args:
        results_path (str, optional): _description_. Defaults to "results.csv".
        attacks_results_path (str, optional): _description_. Defaults to "results_per_attack.csv".

    Returns:
        _type_: _description_
    """
    
    results_df = pd.read_csv(results_path)
    results_per_attack_df = pd.read_csv(attacks_results_path)
    
    return results_df, results_per_attack_df

def load_thresh(path="threshold.csv"):
    """_summary_

    Args:
        path (str, optional): _description_. Defaults to "threshold.csv".

    Returns:
        _type_: _description_
    """
    thresh_df = pd.read_csv(path)
    
    return thresh_df
    
def alert_vol_per_rule(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_
    """
    number_of_alerts = {}
    
    for rule in RULES_LIST:
        number_of_alerts[rule + "_volume"] = int(alerts_df['rule'].str.contains(rule, na=False).sum())
    
    # print(number_of_alerts)
        
def rank_rules_by_noise(results_df):
    rules_sorted_by_FP = results_df.sort_values(by=["FP"], ascending=False)
    # print(rules_sorted_by_FP)
    
    return rules_sorted_by_FP
       
def alert_vol_over_time(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    
    alerts_df['Timestamp'] = pd.to_datetime(alerts_df['Timestamp'])
    alerts_df_sorted = alerts_df.sort_values(by=['Timestamp', 'rule'])
    
    hourly_alerts_count = (
        alerts_df_sorted.set_index('Timestamp')
        .groupby(['rule'])
        .resample('h')
        .size()
        .reset_index(name='count')
        .sort_values(by=['rule', 'Timestamp', 'count'], ascending=[True, True, False])
    )
    
    # print(hourly_alerts_count)
    
    return hourly_alerts_count

def mark_false_positive(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    
    targets_per_row = alerts_df["rule"].map(RULES_TARGETS)
    alerts_df["is_fp"] = [lbl not in tgts for lbl, tgts in zip(alerts_df["Label"], targets_per_row)]
    
    return alerts_df
    
    
    
    
def noisiest_sources(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    fps = alerts_df[alerts_df["is_fp"]]
    
    top_talkers = fps.groupby("Source IP").size().sort_values(ascending=False).head(10)
    noisiest_raw_FP_count = fps.groupby("rule").size().sort_values(ascending=False)
    benign_tripping_rule = fps.groupby(["rule", "Label"]).size().sort_values(ascending=False)
    
    
    return top_talkers, noisiest_raw_FP_count, benign_tripping_rule

def flood_magnitude_composite(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    flood_mask = alerts_df["rule"] == "dos_flood"
    flood = alerts_df[flood_mask]
    
    flow_packets_col = flood["Flow Packets/s"]
    flow_bytes_col = flood["Flow Bytes/s"]
    total_fwd_packets_col = flood["Total Fwd Packets"]
        
    norm_packets = (flow_packets_col - flow_packets_col.min()) / (flow_packets_col.max() - flow_packets_col.min())
    norm_bytes = (flow_bytes_col - flow_bytes_col.min()) / (flow_bytes_col.max() - flow_bytes_col.min())
    norm_fwd = (total_fwd_packets_col - total_fwd_packets_col.min()) / (total_fwd_packets_col.max() - total_fwd_packets_col.min())
    
    composite = (norm_bytes + norm_packets + norm_fwd) / 3
    
    alerts_df.loc[flood_mask, "magnitude"] = composite
    
    return alerts_df
    

def calculate_magnitude(alerts_df, thresh_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_
        thresh_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    
    flood_thresh = thresh_df.loc[thresh_df['Metric'] == 'Flow Packets/s', 'Value'].iloc[0]
    flow_thresh = thresh_df.loc[thresh_df['Metric'] == 'Flow Duration', 'Value'].iloc[0]
    RATE_THRESHOLD = 20
    
    # non_flood = alerts_df["rule"] != "dos_flood"
    dos_flood_mask = alerts_df["rule"] == "dos_flood"
    dos_slow_mask = alerts_df["rule"] == "dos_low_and_slow"
    brute_force_mask = alerts_df["rule"] == "brute_force_rate"
    
    alerts_df.loc[dos_flood_mask, "raw_ratio"] = alerts_df.loc[dos_flood_mask, "Flow Packets/s"] / flood_thresh
    alerts_df.loc[dos_slow_mask, 'raw_ratio'] = alerts_df.loc[dos_slow_mask, "Flow Duration"] / flow_thresh
    alerts_df.loc[brute_force_mask, 'raw_ratio'] = alerts_df.loc[brute_force_mask, "attempts"] / RATE_THRESHOLD
    
    
    alerts_df["magnitude"] = np.log1p(alerts_df['raw_ratio'])
    # alerts_df.loc[non_flood, "magnitude"] = np.log1p(alerts_df.loc[non_flood, "raw_ratio"])
    
    # alerts_df = flood_magnitude_composite(alerts_df)

    # # sanity checks
    # print(alerts_df[alerts_df["magnitude"] == alerts_df["magnitude"].min()][["rule", "Flow Packets/s", "Flow Duration", "attempts", "magnitude"]])
    # print(alerts_df["magnitude"].describe())
    # print(alerts_df["magnitude"].isna().sum()) # should be 0
    # print((alerts_df["magnitude"] < 0.69).sum()) # should be ~0
    
    return alerts_df

def alerts_per_source_ip(alerts_df):
    """_summary_

    Args:
        alerts_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    # print(alerts_df.groupby("rule")["Source IP"].nunique())
    
    source_ip_count = alerts_df.groupby("Source IP").size()
    # print(source_ip_count)
    alerts_df["source_volume"] = alerts_df["Source IP"].map(source_ip_count).fillna(0)
    alerts_df["source_volume_log"] = np.log1p(alerts_df["source_volume"])

    return alerts_df
  
def assign_priority_score(results_df, alerts_df):    
    """_summary_

    Args:
        results_df (_type_): _description_
        alerts_df (_type_): _description_
    """
    SEVERITY = {"dos_flood": 3, "dos_low_and_slow": 3, "brute_force_rate": 1}
    rule_confidence = dict(zip(results_df['rule'],results_df ['precision']))
    
    alerts_df["severity"] = alerts_df["rule"].map(SEVERITY)
    alerts_df["confidence"] = alerts_df["rule"].map(rule_confidence)
    alerts_df["priority_score"] = alerts_df["severity"] * alerts_df["confidence"]
    alerts_df = alerts_df.sort_values(by=["priority_score", "magnitude"], ascending=False)
    alerts_df = alerts_df.reset_index(drop=True)
    
    # print(alerts_df.groupby("rule")[["severity", "confidence", "priority_rank"]].first())
    
    alerts_df.to_csv('priority_queue.csv', columns=['Source IP', 'Destination IP', 
                                                    'Destination Port', 'rule',
                                                    'Label', 'magnitude', 
                                                    'priority_score', 'is_fp'])

def load_priority_queue(path = "priority_queue.csv"):
    """_summary_

    Args:
        path (str, optional): _description_. Defaults to "priority_queue.csv".

    Returns:
        _type_: _description_
    """
    priority_queue_df = pd.read_csv(path)
    
    return priority_queue_df

def get_top_n_percent(priority_queue_df):
    """_summary_

    Args:
        priority_queue_df (_type_): _description_

    Returns:
        _type_: _description_
    """
    total_tp = (~priority_queue_df["is_fp"]).sum()
    total_fp = priority_queue_df["is_fp"].sum()
    total_alerts = len(priority_queue_df.index)
    
    # print(f"Total Alerts: {total_alerts}")
    # print(f"Total TP: {total_tp}")
    # print(f"Total FP: {total_fp}")
    
    top_n_percent_data_list = []
    
    for percentage_cutoff in np.arange(0.0, 1.1, 0.1):
        percent_slice = priority_queue_df.head(int(total_alerts * percentage_cutoff))
        percent_slice_tp = (~percent_slice["is_fp"]).sum()
        percent_slice_fp = percent_slice["is_fp"].sum()
        
        coverage_retained = round((percent_slice_tp / total_tp), 3)
        noise_skipped = round(((total_fp - percent_slice_fp) / total_fp), 3)
        
        # print(f"Coverage Retained: {coverage_retained}")
        # print(f"Noise Skipped: {noise_skipped}")
        
        top_n_percent_data = {"cutoff": round(percentage_cutoff, 1),
                            "coverage": coverage_retained,
                            "noise-skipped": noise_skipped}
        top_n_percent_data_list.append(top_n_percent_data)
    
    top_n_percent_df = pd.DataFrame(top_n_percent_data_list, 
                                    columns=["cutoff", "coverage", "noise-skipped"])
    # print(top_n_percent_df)
    # print(priority_queue_df[["priority_score", "magnitude"]].head(20))
    
    
    top_n_percent_df.to_csv('top_n_percent.csv')
    
    return top_n_percent_df
    
def plot_coverage(top_n_percent_df):
    """_summary_

    Args:
        top_n_percent_df (_type_): _description_
    """
    
    
    fig, ax = plt.subplots(figsize=(8,4))
    
    ax.plot(top_n_percent_df['cutoff'], top_n_percent_df['coverage'], label='coverage', color='blue', marker="o")
    ax.plot(top_n_percent_df['cutoff'], top_n_percent_df['noise-skipped'], label='noise-skipped', color='orange', marker="o")
    
    ax.axline((0.0, 0), slope=1, color='grey', linestyle='--', label="random ordering (reference)")    
    ax.axvline(x=0.65, color="grey", linestyle=":", alpha=0.6)
    
    ax.text(0.66, 0.5, "false positives\nconcentrated below here",
            fontsize=10, color="black", va="center")
    
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    ax.set_xlabel("fraction of queue worked")
    ax.set_ylabel("fraction")
    ax.set_title("Priority queue: coverage vs. noise")
    
    ax.legend(loc="upper left")
    plt.savefig("figures/coverage_curve.png", dpi=150, bbox_inches="tight")
    plt.show()
    
    
    
def main():
    alerts_df = load_alert()
    
    results_df, _ = load_results()
    thresh_df = load_thresh()
    
    alerts_df = mark_false_positive(alerts_df)    
    alert_vol_per_rule(alerts_df)
    rank_rules_by_noise(results_df)
    alert_vol_over_time(alerts_df)
    noisiest_sources(alerts_df)
    
    alerts_df = calculate_magnitude(alerts_df, thresh_df)
    alerts_df = alerts_per_source_ip(alerts_df)
    assign_priority_score(results_df, alerts_df)
    
    priority_queue_df = load_priority_queue()
    top_n_percent_df = get_top_n_percent(priority_queue_df)
    plot_coverage(top_n_percent_df)
    
    

if __name__ == '__main__':
    main()