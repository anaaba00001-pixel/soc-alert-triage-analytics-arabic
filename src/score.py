import pandas as pd
from clean import clean_data

RULES_TARGETS = {
    "brute_force_rate": ["FTP-Patator", "SSH-Patator"],
    "dos_flood": ["DoS Hulk", "DoS GoldenEye"],
    "dos_low_and_slow": ["DoS slowloris", "DoS Slowhttptest"],
}

RULE_DAY = {
    "brute_force_rate": "tuesday",
    "dos_flood": "wednesday",
    "dos_low_and_slow": "wednesday"
}

def get_orig_labels():
    """Gets the orignal labels from the clean dataset 

    Returns:
        Dataframe: Returns 3 dataframes: monday_df, tuesday_df, & wednesday_df
    """
    _, tuesday_df, wednesday_df = clean_data()
    
    # #sanity check
    # print('Label' in wednesday_df.columns)
    # print(wednesday_df['Label'].value_counts())
    
    return _, tuesday_df, wednesday_df

def read_csv(path="alerts.csv"):
    """Obtains the alerts.csv file and stores it as a pandas
    data frame

    Args:
        path (str, optional):The name of the csv file. Defaults to "alerts.csv".

    Returns:
        Dataframe: Returns a pandas dataframe containing all the 
        alerts.
    """
    alerts_df = pd.read_csv(path)
    
    # #sanity check to ensure it pulls alerts.csv correctly
    # print(alerts_df["Label"].value_counts())
    
    return alerts_df

def count_true_pos_per_attack(alerts_df):
    tp = {}
    for rule, attacks in RULES_TARGETS.items():
        fired = alerts_df[alerts_df["rule"] == rule]
        counts = fired["Label"].value_counts()
        for a in attacks:
            tp[(rule, a)] = int(counts.get(a, 0))    
    # print(tp)
    return tp
    
def score(alerts_df, tp):
    _, tue, wed = get_orig_labels()
    totals = {
        "tuesday": tue["Label"].value_counts(),
        "wednesday": wed["Label"].value_counts()
    }
    
    rows = []
    for rule, attacks in RULES_TARGETS.items():
        fired = alerts_df[alerts_df["rule"] == rule ]
        rule_tp = sum(tp.get((rule, a), 0) for a in attacks)
        fp = len(fired) - rule_tp
        day_totals = totals[RULE_DAY[rule]]
        attack_total = sum(int(day_totals.get(a, 0)) for a in attacks)
        fn = attack_total - rule_tp
        
        precision = rule_tp / (rule_tp + fp) if (rule_tp+fp) else 0
        recall = rule_tp / (rule_tp + fn) if (rule_tp + fn) else 0
        
        rows.append({
            "rule": rule,
            "targets": ", ".join(attacks),
            "alerts": len(fired),
            "TP": rule_tp, "FP": fp, "FN": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
        })
    
    return pd.DataFrame(rows)

def score_per_attack(alerts_df, tp):
    _, tue, wed = clean_data()
    totals = {
        "tuesday": tue["Label"].value_counts(),
        "wednesday": wed["Label"].value_counts()
    }
    
    rows = []
    for rule, attacks in RULES_TARGETS.items():
        fired = alerts_df[alerts_df["rule"] == rule]
        rule_tp = sum(tp.get((rule, a), 0) for a in attacks)
        rule_fp = len(fired) - rule_tp
        
        rule_precision = rule_tp / (rule_tp + rule_fp) if (rule_tp + rule_fp) else 0
        
        day = totals[RULE_DAY[rule]]
        for a in attacks:
            a_tp = tp.get((rule, a), 0)
            a_total = int(day.get(a, 0))
            a_fn = a_total - a_tp
            a_recall = a_tp / a_total if a_total else 0
            rows.append({
                "rule": rule,
                "attack": a,
                "TP": a_tp,
                "total_in_data": a_total,
                "FN": a_fn,
                "recall": round(a_recall, 3),
                "rule_precision": round(rule_precision, 3),
            })
    return pd.DataFrame(rows)

def save_results(rule_table, attack_table,
                 rule_path="results.csv", 
                 attack_path="results_per_attack.csv"):

    rule_table.to_csv(rule_path, index=False)
    attack_table.to_csv(attack_path, index=False)
    
    
def main():
    # get_orig_labels()
    alerts_df = read_csv()
    tp = count_true_pos_per_attack(alerts_df)
    
    rule_table = score(alerts_df, tp)
    attack_table = score_per_attack(alerts_df, tp)
    
    print(rule_table.to_string(index=False))
    print(attack_table.to_string(index=False))
    
    save_results(rule_table, attack_table)
    

if __name__ == "__main__":
    main()