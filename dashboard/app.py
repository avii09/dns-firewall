import streamlit as st
from attack import start_raw_attack
from firewall import firewall_tab
from comparative_analysis import show_comparative_analysis

def main():
    st.title("DNS Firewall Dashboard")

    # Create 3 tabs
    tab1, tab2, tab3 = st.tabs(["🛡️ Attack", "🔒 Firewall", "📊 Comparative Analysis"])

    with tab1:
        start_raw_attack()

    with tab2:
        firewall_tab()

    with tab3:
        show_comparative_analysis()

if __name__ == "__main__":
    main()
