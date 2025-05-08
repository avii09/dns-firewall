import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
import os
from matplotlib.patches import Patch
import subprocess

def show_comparative_analysis():
    st.subheader("📊 Comparative Analysis")
    st.markdown("Compare DNS traffic **before attack** and **after firewall filtering**.")

    # Add configuration options
    with st.expander("📋 Analysis Configuration", expanded=False):
        col1, col2 = st.columns(2)
        with col1:
            time_interval = st.selectbox(
                "Time Grouping",
                ["1s", "5s", "10s", "30s", "1min"],
                index=0,
                help="Group data points by time interval"
            )
            
            chart_type = st.selectbox(
                "Chart Type",
                ["Line", "Area", "Bar"],
                index=1,
                help="Select visualization type"
            )
            
        with col2:
            show_blocked = st.checkbox("Show Blocked Traffic", value=True, 
                                      help="Display blocked traffic as a separate series")
            highlight_anomalies = st.checkbox("Highlight Anomalies", value=True,
                                             help="Detect and highlight traffic spikes")

    # File paths
    before_path = "/mnt/97gb/projects/dns-firewall/logs/dns_query_log.csv"
    after_path = "/mnt/97gb/projects/dns-firewall/logs/not_blocked.csv"
    
    # Check if files exist before proceeding
    if not os.path.exists(before_path) or not os.path.exists(after_path):
        st.error("Required log files not found. Please run the firewall analysis first.")
        return
    
    # Comparative analysis button to display visualizations
    compare_button = st.button("🧐 Show Comparative Analysis")

    if compare_button:
        # Load CSVs
        before_df = pd.read_csv(before_path)
        after_df = pd.read_csv(after_path)

        # Convert timestamps
        before_df['timestamp'] = pd.to_datetime(before_df['Timestamp'], unit='s')
        after_df['timestamp'] = pd.to_datetime(after_df['Timestamp'], unit='s')

        # Group by selected time interval
        grouped_before = before_df.groupby(pd.Grouper(key='timestamp', freq=time_interval)).size().reset_index(name='Before Attack')
        grouped_after = after_df.groupby(pd.Grouper(key='timestamp', freq=time_interval)).size().reset_index(name='After Filtering')

        # Merge for comparison
        comparison_df = pd.merge(grouped_before, grouped_after, on='timestamp', how='outer').fillna(0)

        # Calculate blocked traffic
        comparison_df['Blocked'] = comparison_df['Before Attack'] - comparison_df['After Filtering']
        comparison_df['Blocked'] = comparison_df['Blocked'].apply(lambda x: max(0, x))  # Ensure no negative values

        # Plot
        fig, ax = plt.subplots(figsize=(12, 6))

        # Set style
        plt.style.use('ggplot')

        # Determine chart type and create visualization
        if chart_type == "Line":
            ax.plot(comparison_df['timestamp'], comparison_df['Before Attack'], 
                   label='Before Attack', color='#3498db', lw=2)
            ax.plot(comparison_df['timestamp'], comparison_df['After Filtering'], 
                   label='After Filtering', color='#2ecc71', lw=2)
            if show_blocked:
                ax.plot(comparison_df['timestamp'], comparison_df['Blocked'], 
                       label='Blocked Traffic', color='#e74c3c', lw=2, linestyle='--')

        elif chart_type == "Area":
            # Create stacked area chart
            if show_blocked:
                ax.fill_between(comparison_df['timestamp'], 0, comparison_df['After Filtering'], 
                               label='Allowed Traffic', alpha=0.7, color='#2ecc71')
                ax.fill_between(comparison_df['timestamp'], comparison_df['After Filtering'], 
                               comparison_df['Before Attack'], label='Blocked Traffic', 
                               alpha=0.7, color='#e74c3c')
                ax.plot(comparison_df['timestamp'], comparison_df['Before Attack'], 
                       color='#34495e', lw=1, alpha=0.8)
            else:
                ax.fill_between(comparison_df['timestamp'], 0, comparison_df['Before Attack'], 
                               label='Before Attack', alpha=0.6, color='#3498db')
                ax.fill_between(comparison_df['timestamp'], 0, comparison_df['After Filtering'], 
                               label='After Filtering', alpha=0.8, color='#2ecc71')

        else:  # Bar chart
            bar_width = 0.35
            x = np.arange(len(comparison_df))

            ax.bar(x - bar_width/2, comparison_df['Before Attack'], 
                  bar_width, label='Before Attack', color='#3498db', alpha=0.7)
            ax.bar(x + bar_width/2, comparison_df['After Filtering'], 
                  bar_width, label='After Filtering', color='#2ecc71', alpha=0.7)

            # Adjust x-axis for bar chart
            ax.set_xticks(x)
            ax.set_xticklabels([t.strftime('%H:%M:%S') for t in comparison_df['timestamp']], 
                               rotation=45, ha='right')

        # Formatting
        ax.set_title("DNS Traffic: Before vs After Firewall Filtering", fontsize=16, pad=20)
        ax.set_xlabel("Time", fontsize=12)
        ax.set_ylabel("Query Count", fontsize=12)

        # Format x-axis to show time properly
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.xticks(rotation=45)

        # Add grid but make it subtle
        ax.grid(True, linestyle='--', alpha=0.7)

        # Add legend with better placement
        ax.legend(loc='upper left', frameon=True, fancybox=True, shadow=True)

        # Tight layout to ensure everything fits
        fig.tight_layout()

        # Display the chart
        st.pyplot(fig)

        # Add key metrics in a more visual way
        st.markdown("### Key Metrics")

        col1, col2, col3, col4 = st.columns(4)

        # Calculate metrics
        total_before = int(comparison_df['Before Attack'].sum())
        total_after = int(comparison_df['After Filtering'].sum())
        blocked = total_before - total_after
        block_rate = round((blocked / total_before * 100), 1) if total_before > 0 else 0

        # Display metrics in columns with visual indicators
        with col1:
            st.metric("Total Queries", f"{total_before:,}", delta=None)

        with col2:
            st.metric("Allowed Queries", f"{total_after:,}", 
                     delta=f"-{blocked:,}", delta_color="off")

        with col3:
            st.metric("Blocked Queries", f"{blocked:,}", 
                     delta=f"{block_rate}%", delta_color="inverse")

        with col4:
            peak_traffic = int(comparison_df['Before Attack'].max())
            peak_time = comparison_df.loc[comparison_df['Before Attack'].idxmax(), 'timestamp'].strftime('%H:%M:%S')
            st.metric("Peak Traffic", f"{peak_traffic:,}", 
                     delta=f"at {peak_time}", delta_color="off")

        # Distribution visualization
        st.markdown("### Traffic Distribution")

        col1, col2 = st.columns(2)

        with col1:
            # Create pie chart for traffic distribution
            labels = ['Allowed', 'Blocked']
            sizes = [total_after, blocked]
            colors = ['#2ecc71', '#e74c3c']

            fig1, ax1 = plt.subplots(figsize=(6, 4))
            ax1.pie(sizes, labels=None, autopct='%1.1f%%', startangle=90, colors=colors,
                   wedgeprops={'width': 0.4, 'edgecolor': 'w', 'linewidth': 1})

            # Create custom legend
            legend_elements = [
                Patch(facecolor='#2ecc71', label=f'Allowed: {total_after:,}'),
                Patch(facecolor='#e74c3c', label=f'Blocked: {blocked:,}')
            ]
            ax1.legend(handles=legend_elements, loc="center")

            ax1.set_title('Traffic Processing Distribution')
            ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            st.pyplot(fig1)

        with col2:
            # Create a time-based blocking effectiveness chart
            effectiveness_df = comparison_df.copy()
            effectiveness_df['Block Rate'] = (effectiveness_df['Blocked'] / 
                                              effectiveness_df['Before Attack'] * 100).fillna(0)

            fig2, ax2 = plt.subplots(figsize=(6, 4))
            ax2.plot(effectiveness_df['timestamp'], effectiveness_df['Block Rate'], 
                    color='#9b59b6', lw=2, marker='o', markersize=4)
            ax2.set_ylim(0, 100)
            ax2.set_title('Firewall Blocking Effectiveness')
            ax2.set_xlabel('Time')
            ax2.set_ylabel('Block Rate (%)')
            st.pyplot(fig2)
