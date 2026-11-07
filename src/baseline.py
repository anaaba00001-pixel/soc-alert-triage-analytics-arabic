import pandas as pd
from clean import clean_data

def get_baseline():
    """Gets the Monday baseline results for port 80.

    Returns:
        Dict: Returns a dictionary containing the results 
    """
    monday_df, _, _ = clean_data()
    
    #monday ~ benign
    mon_begnign = monday_df[monday_df['Label'] == 'BENIGN']

    #get baseline port 80
    mon_port_80 = mon_begnign[mon_begnign['Destination Port'] == 80]

    #store the features to be used as baseline DoS port 80
    #pre tuned
    # features = [('Flow Packets/s', 0.995, "high", None), 
    #             ('Flow Duration', 0.99, "high", None), 
    #             ('Flow Bytes/s', 0.05, "low", ("Flow Duration", 0.99)),
    #             ('Flow IAT Max', 0.95, "high", None)]
    
    #tuned; 
    # 1. tuned flow packets/s threshold from 0.995 -> 0.90
    # 2. tuned flow bytes/s threshold from 0.05 -> 0.25
    features = [('Flow Packets/s', 0.90, "high", None), 
                ('Flow Duration', 0.50, "high", None), 
                ('Flow Bytes/s', 0.25, "low", ("Flow Duration", 0.99)),
                ('Flow IAT Max', 0.95, "high", None)]

    #loop over the features and calculate the percentile 
    port_80_results_dict = {}

    for feature, level, direction, condition in features:
        baseline = "global"
        base = mon_port_80
        
        if condition is not None:
            cond_feat, cond_level = condition
            cutoff = mon_port_80[cond_feat].quantile(cond_level)
            base = mon_port_80[mon_port_80[cond_feat] > cutoff]
            baseline = f"{cond_feat} > p{int(cond_level*100)}"
        
        col = base[feature].dropna()
        port_80_results_dict[(feature, 80)] = {"Value": col.quantile(level),
                                            "Direction": direction,
                                            "Level": level,
                                            "N": int(len(col)),
                                            "Baseline": baseline}

    # print(port_80_results_dict)
    return port_80_results_dict


def save_to_csv(port_80_results_dict, path="threshold.csv"):
    """Saves the results to a csv file.

    Args:
        port_80_results_dict (Dict): Is passed the port 809 results dictionary
    """
    rows = [
        {'Metric': feat, 'Port': port, **vals}
        for (feat, port), vals in port_80_results_dict.items()
    ]       
    df = pd.DataFrame(rows)
    # pre tuned
    # df.to_csv("threshold.csv", index=False)
    
    # tuned
    df.to_csv(path, index=False)

def main():
    baseline_results = get_baseline()
    save_to_csv(baseline_results)

if __name__ == '__main__':
    main()