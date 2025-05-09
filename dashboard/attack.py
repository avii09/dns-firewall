import streamlit as st
import subprocess
import time
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def start_raw_attack():
    st.subheader("🚨 Raw DNS Attack Simulation")
    st.markdown("Click the button below to launch a **Raw DNS Attack** and visualize DNS traffic patterns.")

    # Button to trigger the raw DNS attack
    attack_button = st.button("Launch Raw DNS Attack")
    if attack_button:
        with st.spinner('🛑 Attack in progress...'):
            try:
                # Run the attack script
                subprocess.run(["sudo", "python3", "/mnt/97gb/projects/dns-firewall/simulator/raw_attack.py"], check=True)

                # Success message after launching attack
                st.success("Raw DNS Attack launched successfully!")

                # Wait for a while to allow log data to be written
                time.sleep(5)

                try:
                    # Read DNS query log file
                    df = pd.read_csv('/mnt/97gb/projects/dns-firewall/logs/dns_query_log.csv')
                    st.write("### DNS Query Log")
                    st.dataframe(df)

                    # Convert timestamp to datetime for better plotting
                    df['timestamp'] = pd.to_datetime(df['Timestamp'], unit='s')

                    # Group data by second and count queries
                    df_grouped = df.groupby(pd.Grouper(key='timestamp', freq='1s')).size().reset_index(name='query_count')

                    # Display traffic graph
                    st.markdown("### 📈 DNS Traffic Over Time (requests per second)")
                    st.line_chart(df_grouped.rename(columns={'timestamp': 'Time'}).set_index('Time')['query_count'])

                    # Check if the traffic exceeds the threshold
                    total_queries = len(df)
                    if total_queries > 30:  # Default threshold
                        st.error(f"🚨 High DNS query traffic detected: {total_queries} queries!")
                    else:
                        st.success(f"✅ Traffic is within normal range: {total_queries} queries.")

                except FileNotFoundError:
                    st.error("⚠️ Log file not found. Ensure the attack was executed properly and the log file exists.")

            except subprocess.CalledProcessError as e:
                st.error(f"[ERROR] Attack failed with error: {e}")
