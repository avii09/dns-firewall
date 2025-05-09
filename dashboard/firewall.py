import streamlit as st
import subprocess
import time
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def firewall_tab():
    st.subheader("Firewall Protection")

    if st.button("Activate Firewall & Analyze Traffic"):
        with st.spinner('Analyzing traffic...'):
            try:
                result = subprocess.run(
                    ["sudo", "python3", "/mnt/97gb/projects/dns-firewall/simulator/main.py"], check=True
                )

                if result.returncode == 0:
                    st.success("[*] Firewall analysis completed successfully!")
                    time.sleep(5)

                    st.write("### Firewall Analysis Results:")

                    # Load all logs with error handling
                    try:
                        # Load dataframes with explicit error handling
                        try:
                            rate_df = pd.read_csv('/mnt/97gb/projects/dns-firewall/logs/rate_limiter_logs.csv')
                        except FileNotFoundError:
                            st.warning("Rate limiter logs not found. Using empty dataframe.")
                            rate_df = pd.DataFrame(columns=['Status', 'IP', 'Domain', 'Timestamp', 'Current_Count', 'Threshold'])
                        
                        try:
                            yara_df = pd.read_csv('/mnt/97gb/projects/dns-firewall/logs/yara_matched.csv')
                        except FileNotFoundError:
                            st.warning("YARA logs not found. Using empty dataframe.")
                            yara_df = pd.DataFrame(columns=['Domain', 'IP', 'Rules', 'Timestamp'])
                        
                        try:
                            # Load the BLOCKED IPs from to_block.csv instead of not_blocked.csv
                            blocked_df = pd.read_csv('/mnt/97gb/projects/dns-firewall/logs/to_block.csv')
                            # Ensure we have an 'IP' column (according to your sample data, it should exist)
                            if 'IP' not in blocked_df.columns:
                                if 'Spoofed_IP' in blocked_df.columns:
                                    blocked_df = blocked_df.rename(columns={'Spoofed_IP': 'IP'})
                                elif 'K' in blocked_df.columns and 'K' != 'IP':  # Based on your sample data
                                    st.warning("Column 'IP' not found in to_block.csv but 'K' column found. Check CSV format.")
                            
                            # Load the allowed (not blocked) IPs for comparison
                            try:
                                allowed_df = pd.read_csv('/mnt/97gb/projects/dns-firewall/logs/not_blocked.csv')
                            except FileNotFoundError:
                                allowed_df = pd.DataFrame(columns=['Timestamp', 'Domain', 'IP'])
                                
                        except FileNotFoundError:
                            st.warning("Blocked IPs logs not found. Using empty dataframe.")
                            blocked_df = pd.DataFrame(columns=['K', 'IP', 'Domain', 'Timestamp', 'Current_Count', 'Threshold'])
                            allowed_df = pd.DataFrame(columns=['Timestamp', 'Domain', 'IP'])
                        
                        try:
                            dns_df = pd.read_csv('/mnt/97gb/projects/dns-firewall/logs/dns_query_log.csv')
                        except FileNotFoundError:
                            st.warning("DNS query logs not found. Using empty dataframe.")
                            dns_df = pd.DataFrame(columns=['Timestamp', 'Spoofed_IP', 'Domain', 'Query_Type', 'Query_Name'])

                        # Display logs
                        st.write("### Rate Limiting Logs:")
                        if not rate_df.empty:
                            st.dataframe(rate_df)
                        else:
                            st.info("No rate limiting data available.")

                        st.write("### Logs After Filtering:")
                        if not yara_df.empty:
                            st.dataframe(yara_df)
                        else:
                            st.info("No YARA rule matches found.")

                        st.write("### Blocked IPs by Firewall:")
                        if not blocked_df.empty:
                            st.dataframe(blocked_df)
                        else:
                            st.info("No blocked IPs data available.")
                            
                        # If we have both blocked and allowed data, show a comparison
                        if 'allowed_df' in locals() and not allowed_df.empty and not blocked_df.empty:
                            st.write("### Firewall Effectiveness Overview:")
                            
                            # Calculate totals
                            total_blocked = len(blocked_df)
                            total_allowed = len(allowed_df)
                            total_traffic = total_blocked + total_allowed
                            
                            # Create columns for metrics
                            col1, col2, col3 = st.columns(3)
                            
                            with col1:
                                st.metric("Total Traffic", f"{total_traffic} queries")
                            
                            with col2:
                                st.metric("Blocked", f"{total_blocked} queries", 
                                          f"{(total_blocked/total_traffic*100):.1f}%")
                            
                            with col3:
                                st.metric("Allowed", f"{total_allowed} queries", 
                                          f"{(total_allowed/total_traffic*100):.1f}%")

                        # Rate limiting visualization - showing current vs threshold values
                        st.markdown("### 📊 DNS Traffic Rate Limiting Analysis")
                        
                        if not rate_df.empty and all(col in rate_df.columns for col in ['IP', 'Current_Count', 'Threshold']):
                            # Focus on IPs approaching their threshold (potential threats)
                            rate_df['Threshold_Percentage'] = (rate_df['Current_Count'] / rate_df['Threshold'] * 100).round(1)
                            
                            # Group by IP and get max threshold percentage
                            ip_threat_level = rate_df.groupby('IP')['Threshold_Percentage'].max().reset_index()
                            ip_threat_level = ip_threat_level.sort_values('Threshold_Percentage', ascending=False).head(10)
                            
                            if not ip_threat_level.empty:
                                fig, ax = plt.subplots(figsize=(12, 6))
                                
                                # Create horizontal gauge-like chart
                                bars = ax.barh(ip_threat_level['IP'], ip_threat_level['Threshold_Percentage'], color='#3498db')
                                
                                # Add threshold line at 100%
                                ax.axvline(x=100, color='red', linestyle='--', alpha=0.7, label='Threshold')
                                
                                # Color bars based on threshold percentage
                                for i, bar in enumerate(bars):
                                    percentage = ip_threat_level['Threshold_Percentage'].iloc[i]
                                    if percentage >= 75:
                                        bar.set_color('#e74c3c')  # Red for high risk
                                    elif percentage >= 50:
                                        bar.set_color('#f39c12')  # Orange for medium risk
                                    else:
                                        bar.set_color('#2ecc71')  # Green for low risk
                                
                                # Add percentage labels on bars
                                for i, v in enumerate(ip_threat_level['Threshold_Percentage']):
                                    ax.text(max(v + 1, 5), i, f"{v}%", va='center', fontsize=9)
                                
                                # Customize plot
                                ax.set_title('Top 10 IPs Approaching Rate Limit Thresholds', fontsize=16)
                                ax.set_xlabel('Threshold Percentage (%)', fontsize=12)
                                ax.set_ylabel('IP Address', fontsize=12)
                                ax.set_xlim(0, max(125, ip_threat_level['Threshold_Percentage'].max() * 1.1))
                                
                                # Add legend explaining colors
                                from matplotlib.patches import Patch
                                legend_elements = [
                                    Patch(facecolor='#2ecc71', label='Low Risk (<50%)'),
                                    Patch(facecolor='#f39c12', label='Medium Risk (50-75%)'),
                                    Patch(facecolor='#e74c3c', label='High Risk (>75%)'),
                                    Patch(facecolor='white', edgecolor='red', linestyle='--', label='Threshold')
                                ]
                                ax.legend(handles=legend_elements, loc='lower right')
                                
                                plt.tight_layout()
                                st.pyplot(fig)
                                
                                # Add a secondary visualization showing domain frequency
                                if 'Domain' in rate_df.columns:
                                    st.markdown("#### Most Frequently Queried Domains")
                                    
                                    domain_counts = rate_df['Domain'].value_counts().reset_index()
                                    domain_counts.columns = ['Domain', 'Query Count']
                                    domain_counts = domain_counts.sort_values('Query Count', ascending=False).head(5)
                                    
                                    # Use pie chart for domain distribution
                                    fig, ax = plt.subplots(figsize=(10, 6))
                                    explode = [0.1 if i == 0 else 0 for i in range(len(domain_counts))]
                                    
                                    wedges, texts, autotexts = ax.pie(
                                        domain_counts['Query Count'], 
                                        explode=explode,
                                        labels=domain_counts['Domain'], 
                                        autopct='%1.1f%%',
                                        textprops={'fontsize': 9},
                                        colors=plt.cm.Paired(np.linspace(0, 1, len(domain_counts))),
                                        shadow=True, 
                                        startangle=90
                                    )
                                    
                                    # Customize pie chart
                                    ax.set_title('Top Domains in DNS Traffic', fontsize=14)
                                    ax.axis('equal')  # Equal aspect ratio ensures pie is circular
                                    
                                    plt.tight_layout()
                                    st.pyplot(fig)
                            else:
                                st.info("Not enough rate limiting data to create visualization.")
                        else:
                            st.info("Rate limiting data missing required columns (IP, Current_Count, Threshold).")
                        
                        
                        # Calculate and display firewall effectiveness
                        total_queries = len(dns_df)
                        
                        # Add a visual representation of blocked vs. allowed traffic
                        st.markdown("### 📊 Firewall Blocking Effectiveness")
                        
                        # Safely check for IP column in blocked_df
                        blocked_ips = []
                        if 'IP' in blocked_df.columns:
                            blocked_ips = blocked_df['IP'].unique()
                            blocked_count = len(blocked_ips)
                        else:
                            st.warning("'IP' column not found in to_block.csv. Check CSV format.")
                            blocked_count = 0
                        
                        # Create a visualization showing blocked domains/IPs
                        if blocked_count > 0:
                            # Create a pie chart showing blocked vs allowed
                            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
                            
                            # First pie chart: Blocked vs. Allowed
                            if 'allowed_df' in locals() and not allowed_df.empty:
                                allowed_count = len(allowed_df)
                                total = blocked_count + allowed_count
                                
                                labels = ['Blocked', 'Allowed']
                                sizes = [blocked_count, allowed_count]
                                colors = ['#e74c3c', '#2ecc71']
                                
                                ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', 
                                       startangle=90, shadow=True, explode=(0.1, 0))
                                ax1.axis('equal')
                                ax1.set_title("Firewall Traffic Distribution", fontsize=14)
                            
                            # Second pie chart: Top Blocked IPs
                            if 'IP' in blocked_df.columns and 'Domain' in blocked_df.columns:
                                # Get top blocked IPs and domains
                                top_blocked_ip_counts = blocked_df['IP'].value_counts().head(5)
                                
                                # If we have data, create the chart
                                if not top_blocked_ip_counts.empty:
                                    wedges, texts, autotexts = ax2.pie(
                                        top_blocked_ip_counts.values,
                                        labels=top_blocked_ip_counts.index,
                                        autopct='%1.1f%%',
                                        textprops={'fontsize': 9},
                                        colors=plt.cm.Reds(np.linspace(0.4, 0.8, len(top_blocked_ip_counts))),
                                        startangle=90
                                    )
                                    ax2.axis('equal')
                                    ax2.set_title("Top Blocked IPs", fontsize=14)
                                
                            plt.tight_layout()
                            st.pyplot(fig)
                            
                            # Show domains associated with blocked IPs
                            if 'IP' in blocked_df.columns and 'Domain' in blocked_df.columns:
                                st.markdown("### 🔍 Top Blocked Malicious Domains")
                                
                                # Get top blocked domains
                                top_blocked_domains = blocked_df['Domain'].value_counts().head(10).reset_index()
                                top_blocked_domains.columns = ['Domain', 'Count']
                                
                                # Create horizontal bar chart for domains
                                if not top_blocked_domains.empty:
                                    fig, ax = plt.subplots(figsize=(12, 6))
                                    
                                    # Create horizontal bars with color gradient
                                    colors = plt.cm.Reds(np.linspace(0.4, 0.8, len(top_blocked_domains)))
                                    bars = ax.barh(top_blocked_domains['Domain'], top_blocked_domains['Count'], color=colors)
                                    
                                    # Add labels to bars
                                    for i, bar in enumerate(bars):
                                        width = bar.get_width()
                                        ax.text(width + 0.3, bar.get_y() + bar.get_height()/2, 
                                                f"{width}", ha='left', va='center')
                                    
                                    ax.set_title("Top Blocked Malicious Domains", fontsize=16)
                                    ax.set_xlabel("Number of Blocked Requests", fontsize=12)
                                    ax.set_ylabel("Domain", fontsize=12)
                                    
                                    plt.tight_layout()
                                    st.pyplot(fig)
                            
                            # Show warning or success message
                            # if blocked_count > 10:
                            #     st.error(f"🚨 Firewall has blocked {blocked_count} malicious requests from {len(blocked_ips)} unique IPs!")
                            # else:
                            #     st.success(f"✅ Firewall successfully blocked {blocked_count} malicious requests from {len(blocked_ips)} unique IPs.")
                        else:
                            st.warning("⚠️ No blocked traffic detected. Either the firewall is not active or there are no threats.")

                    except Exception as e:
                        st.error(f"[ERROR] Something went wrong during log analysis: {str(e)}")
                        st.info("Debug info: Check if all CSV files have the expected column names.")
            except Exception as e:
                st.error(f"[ERROR] Something went wrong during firewall execution: {str(e)}")