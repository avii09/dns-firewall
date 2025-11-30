import streamlit as st
import subprocess
import time
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os

def start_raw_attack():
    st.subheader("🚨 Raw DNS Attack Simulation")
    st.markdown("Click the button below to launch a **Raw DNS Attack** and visualize DNS traffic patterns.")

    # Initialize session state for attack data
    if 'attack_data' not in st.session_state:
        st.session_state.attack_data = None
    if 'attack_df' not in st.session_state:
        st.session_state.attack_df = None
    if 'attack_df_grouped' not in st.session_state:
        st.session_state.attack_df_grouped = None

    # Button to trigger the raw DNS attack
    attack_button = st.button("Launch Raw DNS Attack")
    if attack_button:
        with st.spinner('🛑 Attack in progress...'):
            try:
                # Use the current Python interpreter (venv) to run the attack script
                # Get the venv Python path
                venv_python = sys.executable
                # Get project root directory (parent of dashboard/)
                PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                script_path = os.path.join(PROJECT_ROOT, "simulator", "raw_attack.py")
                
                # Run the attack script with venv Python (sudo may still be needed for network operations)
                subprocess.run(["sudo", venv_python, script_path], check=True)

                # Success message after launching attack
                st.success("Raw DNS Attack launched successfully!")

                # Wait for a while to allow log data to be written
                time.sleep(5)

                try:
                    # Read DNS query log file
                    log_path = os.path.join(PROJECT_ROOT, "logs", "dns_query_log.csv")
                    df = pd.read_csv(log_path)
                    
                    # Convert timestamp to datetime for better plotting
                    df['timestamp'] = pd.to_datetime(df['Timestamp'], unit='s')

                    # Group data by second and count queries
                    df_grouped = df.groupby(pd.Grouper(key='timestamp', freq='1s')).size().reset_index(name='query_count')

                    # Store in session state
                    st.session_state.attack_data = True
                    st.session_state.attack_df = df
                    st.session_state.attack_df_grouped = df_grouped

                except FileNotFoundError:
                    st.error("⚠️ Log file not found. Ensure the attack was executed properly and the log file exists.")
                    st.session_state.attack_data = None

            except subprocess.CalledProcessError as e:
                st.error(f"[ERROR] Attack failed with error: {e}")
                st.session_state.attack_data = None

    # Display data from session state if available
    if st.session_state.attack_data and st.session_state.attack_df is not None:
        df = st.session_state.attack_df
        df_grouped = st.session_state.attack_df_grouped
        
        st.write("### DNS Query Log")
        st.dataframe(df)

        # Display traffic graph
        st.markdown("### 📈 DNS Traffic Over Time (requests per second)")
        st.line_chart(df_grouped.rename(columns={'timestamp': 'Time'}).set_index('Time')['query_count'])

        # Check if the traffic exceeds the threshold
        total_queries = len(df)
        if total_queries > 30:  # Default threshold
            st.error(f"🚨 High DNS query traffic detected: {total_queries} queries!")
        else:
            st.success(f"✅ Traffic is within normal range: {total_queries} queries.")
