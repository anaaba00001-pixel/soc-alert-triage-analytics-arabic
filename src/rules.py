import pandas as pd
from clean import clean_data


AUTH_PORTS = {21, 22}
ATTEMPT_PER_MIN = 20
## pre tuned values 
# MAX_FWD_PACKES = 8 


#tuned values
MAX_FWD_PACKES = 20


HTTP_PORT = 80

def load_threshold(path="threshold.csv"):
    """_summary_

    Args:
        path (str, optional): _description_. Defaults to "threshold.csv".

    Returns:
        _type_: _description_
    """
    tdf = pd.read_csv(path).dropna(subset=["Metric"])
    tdf["Value"] = pd.to_numeric(tdf["Value"])
    return tdf.set_index(["Metric", "Port"])["Value"].to_dict()

def brute_force_alerts(df):
     """_summary_

     Args:
         df (_type_): _description_

     Returns:
         _type_: _description_
     """
     cand = df[df["Destination Port"].isin(AUTH_PORTS) &
               (df["Total Fwd Packets"] <= MAX_FWD_PACKES)].copy()
     
     cand["ts"] = pd.to_datetime(cand["Timestamp"], dayfirst=True, errors="coerce")
     cand = cand.dropna(subset=["ts"])
     
     cand["window"] = cand["ts"].dt.floor("60s")
     keys = ["Source IP", "Destination IP", "Destination Port", "window"]
     counts = cand.groupby(keys).size().rename("attempts").reset_index()
     
    #  hot_keys = set(map(tuple, counts.loc[counts["attempts"] > ATTEMPT_PER_MIN, keys].values))
    #  cand["is_alert"] = [tuple(k) in hot_keys for k in cand[keys].values]
     
    #  alerts = cand[cand["is_alert"]].drop(columns=["ts", "window", "is_alert"])
    #  alerts["rule"] = "brute_force_rate"
    
     cand = cand.merge(counts, on=keys, how="left")
     alerts = cand[cand["attempts"] > ATTEMPT_PER_MIN].copy()
     alerts = alerts.drop(columns=["ts", "window"])
     alerts["rule"] = "brute_force_rate"
    
     return alerts
 
def dos_flood_alerts(df, thr):
    """_summary_

    Args:
        df (_type_): _description_
        thr (_type_): _description_

    Returns:
        _type_: _description_
    """
    alerts = df[(df["Destination Port"] == HTTP_PORT) &
                (df["Flow Packets/s"] > thr[("Flow Packets/s", HTTP_PORT)])].copy()
    alerts["rule"] = "dos_flood"
    return alerts

def dos_slow_alerts(df, thr):
    """_summary_

    Args:
        df (_type_): _description_
        thr (_type_): _description_

    Returns:
        _type_: _description_
    """
    alerts = df[(df["Destination Port"] == HTTP_PORT) &
                (df["Flow Duration"] > thr[("Flow Duration", HTTP_PORT)]) &
                (df["Flow Bytes/s"] < thr[("Flow Bytes/s", HTTP_PORT)]) &
                (df["Flow IAT Max"] > thr[("Flow IAT Max", HTTP_PORT)])].copy()
    alerts["rule"] = "dos_low_and_slow"
    return alerts

def run_all_rules():
    """_summary_

    Returns:
        _type_: _description_
    """
    monday_df, tuesday_df, wednesday_df = clean_data()
    thr = load_threshold()
    
    alerts = pd.concat([
        brute_force_alerts(tuesday_df),
        dos_flood_alerts(wednesday_df, thr),
        dos_slow_alerts(wednesday_df, thr),
    ], ignore_index=True)
    return alerts

def save_alerts(alerts, path="alerts.csv"):
    """_summary_

    Args:
        alerts (_type_): _description_
        path (str, optional): _description_. Defaults to "alerts.csv".
    """
    alerts.to_csv(path, index=False)
    
def main():
    alerts = run_all_rules()
    # print(alerts["rule"].value_counts())
    # print(alerts['Label'].value_counts())
    save_alerts(alerts)
    
if __name__ == "__main__":
    main()