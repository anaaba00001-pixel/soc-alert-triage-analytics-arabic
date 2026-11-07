import pandas as pd
import numpy as np

def clean_data():
    """This function cleans the following files: Monday-WorkingHours.pcap_ISCX.csv, 
    Tuesday-WorkingHours.pcap_ISCX.csv, and Wednesday-WorkingHours.pcap_ISCX.csv. 
    Removing whitespace within the columns, replacing any INF with NaN, and dropping
    the duplicate column 'Fwd Header Length.1'
    
    Returns: Three cleaned dataframes - monday_df, tuesday_df, wednesday_df
    """
    #reading in the data for mon, tues, and wed

    tuesday_df = pd.read_csv("data/TrafficLabelling/Tuesday-WorkingHours.pcap_ISCX.csv")
    monday_df = pd.read_csv("data/TrafficLabelling/Monday-WorkingHours.pcap_ISCX.csv")
    wednesday_df = pd.read_csv("data/TrafficLabelling/Wednesday-workingHours.pcap_ISCX.csv")

    #cleaning up the column names by stripping the surrounding whitespace

    tuesday_df.columns = tuesday_df.columns.str.strip()
    monday_df.columns = monday_df.columns.str.strip()
    wednesday_df.columns = wednesday_df.columns.str.strip()

    #replace all inf w/ nans
    tuesday_df = tuesday_df.replace([np.inf, -np.inf], np.nan)
    monday_df = monday_df.replace([np.inf, -np.inf], np.nan)
    wednesday_df = wednesday_df.replace([np.inf, -np.inf], np.nan)

    #dropped the duplicate col 'Fwd Header Length.1'
    tuesday_df.drop('Fwd Header Length.1', axis=1, inplace=True)
    monday_df.drop('Fwd Header Length.1', axis=1, inplace=True)
    wednesday_df.drop('Fwd Header Length.1', axis=1, inplace=True)
    
    return monday_df, tuesday_df, wednesday_df