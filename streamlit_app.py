import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import sys
import os
import requests


# To launch the dashboard, PLEASE run: python -m streamlit run streamlit_app.py or streamlit run streamlit_app.py
# === CONFIGURATION ===
NORMAL_FILE = r"data/processed/normal_features.csv"
ISO_FOREST_REPORT = r"data/processed/iso_forest_report.csv"

st.set_page_config(page_title="OT Network Traffic Analysis", layout="wide")


# === SIDEBAR NAVIGATION ===
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["📊 Dashboard", "🤖 Cyber Assistant"])

# === PAGE 1: DASHBOARD ===
if page == "📊 Dashboard":
    st.title("Network Traffic Analysis Report Using Isolation Forest")

    # Load Data 
    try:
        normal_df = pd.read_csv(NORMAL_FILE) 
        anomaly_df = pd.read_csv(ISO_FOREST_REPORT) 
        # --- AUTOMATED ALERT SYSTEM ---
        # Check for critical threats in the loaded anomaly data
        critical_threats = anomaly_df[anomaly_df['threat_type'].str.contains("CRITICAL", na=False)]
        
        if not critical_threats.empty:
            num_critical = len(critical_threats)
            st.toast(f"🚨 ALERT: {num_critical} Critical Threats Detected!", icon="⚠️")
            # Can also add a persistent warning box for visibility
            st.error(f"CRITICAL SECURITY ALERT: {num_critical} unauthorized stop commands or severe anomalies found. Immediate action required!")
               

        # 1. Interactive Pie Chart
        st.subheader("📈 Traffic Overview")
        normal_count = len(normal_df) 
        anomaly_counts = anomaly_df['threat_type'].value_counts().to_dict()
        combined_counts = {"Normal Traffic": normal_count} 
        combined_counts.update(anomaly_counts) 
        counts = pd.Series(combined_counts) 
        total_packets = normal_count + len(anomaly_df) 

        colors = {
            "Normal Traffic": "#90EE90",
            "CRITICAL: UNAUTHORIZED STOP COMMAND": "#cc0000",
            "FOREIGN IP ACCESS": "#ff0000",
            "DoS ATTACK (High Volume)": "#1900ff",
            "Unknown Anomaly (Statistical Deviation)": "#ffaa00"
        }
        pie_colors = [colors.get(x, "#c0c0c0") for x in counts.index]

        fig_pie = go.Figure(data=[go.Pie(
            labels=counts.index,
            values=counts.values,
            marker=dict(colors=pie_colors, line=dict(color='#c0c0c0', width=2)),
            pull=[0.05] * len(counts),
            customdata=counts.index # Pass label for filtering
        )])
        fig_pie.update_layout(title=f"Traffic Overview (Total: {total_packets:,})") 
        
        # Enable Selection
        event = st.plotly_chart(fig_pie, use_container_width=True, on_select="rerun", key="pie_drilldown")
        
        # Handle the Drill-down filtering
        selected_label = None
        if event and "selection" in event and event["selection"]["points"]:
            selected_label = event["selection"]["points"][0]["label"]
            st.info(f"🔎 Filtering for: **{selected_label}**")

        # 2. Attack Breakdown Bar Chart 
        st.subheader("📊 Attack Breakdown by Type")
        anomaly_counts_dict = anomaly_df['threat_type'].value_counts().to_dict()
        anomaly_df_for_chart = pd.DataFrame(list(anomaly_counts.items()), columns=['Threat Type', 'Packets'])
        anomaly_df_for_chart = anomaly_df_for_chart.sort_values('Packets', ascending=True) 
        
        bar_fig = go.Figure(data=[go.Bar(
            y=anomaly_df_for_chart['Threat Type'],
            x=anomaly_df_for_chart['Packets'],
            orientation='h',
            marker=dict(color=[colors.get(t, "#d9d9d9") for t in anomaly_df_for_chart['Threat Type']]),            
            hoverinfo='text',
            text=anomaly_df_for_chart['Packets'],
            textposition='outside'
        )])
        bar_fig.update_layout(xaxis_title="Number of Packets", yaxis_title="Threat Type") 
        st.plotly_chart(bar_fig, use_container_width=True)

        # 3. Traffic Report in Numbers
        st.divider()
        st.subheader("Traffic Report")
        m1, m2 = st.columns(2)
        m1.metric("Normal Traffic", f"{normal_count:,}", f"{100*normal_count/total_packets:.1f}%")
        m2.metric("Anomalies Detected", f"{len(anomaly_df):,}", f"{100*len(anomaly_df)/total_packets:.1f}%", delta_color="inverse")

       
        # 4. Anomaly Breakdown Table
        st.divider()
        st.subheader("Anomaly Breakdown")
        st.caption("Able to download the table as CSV using the top-right menu.")
        breakdown_data = {
        "Normal/Anomaly Traffic": counts.index,
            "Packet Count": counts.values
        }

        breakdown_df = pd.DataFrame(breakdown_data)
        st.dataframe(breakdown_df, use_container_width=True, hide_index=True)

       # 5. Show colored threat type boxes
        threat_types = anomaly_df['threat_type'].unique()
        t_cols = st.columns(len(threat_types) if len(threat_types) > 0 else 1) 

        for idx, t_type in enumerate(threat_types):
            with t_cols[idx]:
                t_count = len(anomaly_df[anomaly_df['threat_type'] == t_type]) 
                t_color = colors.get(t_type, "#d9d9d9") 
                st.markdown(f"""
                    <div style="border-left: 4px solid {t_color}; padding: 12px; background-color: #f9f9f9; border-radius: 5px;">
                        <h4 style="margin: 0; color: {t_color};">{t_type}</h4>
                        <p style="margin: 5px 0 0 0; font-size: 20px; font-weight: bold;">{t_count} packets</p>
                    </div>
                """, unsafe_allow_html=True) 

        # 6. Detailed Detected Anomaly Table with Classification
        st.divider()
        st.subheader("🚨 Anomaly Classification: Malicious vs. Faulty")
        st.caption("Review the detected anomalies and classify them based on OT context.")

        # Prepare the display dataframe
        anomaly_df_display = anomaly_df.copy()

        # Add a 'Classification' column if it doesn't exist
        if 'Classification' not in anomaly_df_display.columns:
            # Updated Pre-fill logic for Anomaly Classification
            def classify_threat(threat_str):
                threat_str = str(threat_str).upper() # Ensure case-insensitivity
    
                # 1. Check for Malicious indicators
                if any(kw in threat_str for kw in ["CRITICAL", "DoS", "FOREIGN"]):
                    return "Malicious"
    
                # 2. Specifically isolate Unknown/Statistical anomalies for investigation
                elif "UNKNOWN ANOMALY" in threat_str or "STATISTICAL" in threat_str:
                    return "Requires Investigation"
    
                 # 3. Everything else defaults to Faulty
                else:
                    return "Faulty"

            # Apply the new function to your display dataframe
            anomaly_df_display['Classification'] = anomaly_df_display['threat_type'].apply(classify_threat)

        # Use st.data_editor to allow user input
        edited_df = st.data_editor(
        anomaly_df_display,
        column_config={
            "Classification": st.column_config.SelectboxColumn(
                "Classification",
                help="Categorize this anomaly",
                options=["Malicious", "Faulty", "Requires Investigation"],
                required=True,
            )
        },   

        disabled=[ "threat_type", "packet_length", "src_ip_str", "delta_time", "src_ip_int", "function_code", "label", "anomaly"], # Lock raw data
        hide_index=True,
        use_container_width=True
        )   

        # Optional: Button to save the classification to a new CSV
        if st.button("💾 Save Classifications"):
            # 1. Create a timestamp string (e.g., 20260201_2245) 24 hour format
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")

            # 2. Construct the new filename
            filename = f"data/processed/classified_anomalies_{timestamp}.csv"
    
            # 3. Ensure folder exists and save
            os.makedirs("data/processed", exist_ok=True)
            edited_df.to_csv(filename, index=False)
    
            st.success(f"✅ Report saved as: {filename} to processed folder!")

        # Comparison Chart
        class_counts = edited_df['Classification'].value_counts()
        fig_class = go.Figure(data=[go.Bar(
            x=class_counts.index,
            y=class_counts.values,
            marker_color=['#ff4b4b', '#00cc96'] # Red for Malicious, Green for Faulty
        )])
        fig_class.update_layout(title="Malicious vs. Faulty Distribution", height=300)
        st.plotly_chart(fig_class, use_container_width=True)

        # 7. Function Code Interpretation Table and Chart
        st.divider()
        st.subheader("🔍 Function Code Analysis")   
        
        # Define the Modbus Function Code Mapping
        function_code_map = {
            1: "Read Coil Status",
            2: "Read Discrete Input Status",
            3: "Read Multiple Holding Registers",
            4: "Read Input Registers",
            5: "Write Single Coil",
            6: "Write Single Holding Register",
            15: "Write Multiple Coils",
            16: "Write Multiple Holding Registers",
            23: "Read/Write Multiple Registers",
            # Common OT-specific or proprietary codes often found in anomalies
            90: "Unity/Schneider Diagnostic (UMAS protocol)",
            127: "Error/Exception Response"
        }

        # Combine normal and anomaly data to see all unique function codes present
        all_data = pd.concat([normal_df, anomaly_df], ignore_index=True)
        
        if 'function_code' in all_data.columns:
            # Extract unique codes and map them
            unique_codes = sorted(all_data['function_code'].dropna().unique())
            
            # Create a summary table
            interpretation_data = []
            for code in unique_codes:
                interpretation_data.append({
                    "Function Code": int(code),
                    "Description": function_code_map.get(int(code), "Unknown/Proprietary Code"),
                    "Total Count": len(all_data[all_data['function_code'] == code])
                })
            
            fc_df = pd.DataFrame(interpretation_data)
            
            # Display using columns for a clean look
            col_a, col_b = st.columns([1, 1])
            with col_a:
                st.write("Modbus operations found in traffic:")
                # Use st.dataframe instead of st.table to allow hiding the index
                st.dataframe(fc_df, hide_index=True, use_container_width=True)
            
            with col_b:
                # Optional: A small bar chart showing the distribution of function codes
                fc_chart = go.Figure(go.Bar(
                    x=fc_df["Function Code"].astype(str),
                    y=fc_df["Total Count"],
                    text=fc_df["Total Count"], # This adds the numbers
                    textposition='outside', # This places them at the top
                    marker_color="#0083B8",
                    cliponaxis=False # Ensures labels aren't cut off at the top
                ))
                fc_chart.update_layout(title="Frequency by Function Code", 
                                       xaxis_title="Code", 
                                       yaxis_title="Packets", 
                                       margin=dict(t=50)) # Adds extra space at top for labels
                st.plotly_chart(fc_chart, use_container_width=True)
        else:
            st.warning("Function code column not found in dataset.")             

    except FileNotFoundError as e:
        st.error(f"Error: {e}. Run analysis scripts first!") 


# === PAGE 2: CYBER ASSISTANT CHATBOT ===
elif page == "🤖 Cyber Assistant":
    st.title("Cybersecurity & OT Assistant")
    st.markdown("Ask about IT/OT security, threats found from analysis report, threat prevention, common cybersecurity threats.")
    st.caption("Scroll up or down to see your previous messages. Chat history is not saved if you refresh the page. To avoid overloading the backend service, please wait a while before asking another question.")
    
    # Initialize Session State for Chat 
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    if "generate_response" not in st.session_state:
        st.session_state.generate_response = False 

    # Chat Container 
    with st.container(height=500):
        for msg in st.session_state.messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

    # Handle AI Response 
    if st.session_state.generate_response:
        with st.spinner("Consulting cybersecurity knowledge base..."):
            try:
                last_user_msg = st.session_state.messages[-1]["content"]
            
                # Updated Webhook for Cybersecurity
                n8n_webhook_url = "https://n8ngc.codeblazar.org/webhook/cyberthreat-chatbot"
            
                response = requests.post(
                    n8n_webhook_url,
                    json={"question": last_user_msg},
                    timeout=30
                ) 
            
                # This checks if the server returned a 429 (Rate Limit) or 500 error
                response.raise_for_status()
            
                res_json = response.json()
                ai_reply = res_json.get("answer", res_json.get("output", "I'm having trouble processing that."))

            except requests.exceptions.HTTPError as http_err:
                # specifically check for the 429 Rate Limit status code
                if response.status_code == 429:
                    ai_reply = "⚠️ The system is a bit overwhelmed right now (Rate Limit reached). Please wait about 10 seconds and try again."
                else:
                    ai_reply = f"⚠️ Server Error: {http_err}"
                
            except Exception as e:  
             # This catches the "Expecting value: line 1 column 1" error 
                # and replaces it with a user-friendly message.
                if "Expecting value" in str(e):
                    ai_reply = "⚠️ The AI service is currently busy or rate-limited. Please try again in a moment."
                else:
                    ai_reply = "⚠️ I encountered an unexpected error. Please try again."

        st.session_state.messages.append({"role": "assistant", "content": ai_reply})
        st.session_state.generate_response = False 
        st.rerun()

    # Chat Input 
    if user_input := st.chat_input("How can I help you today?"):
        st.session_state.messages.append({"role": "user", "content": user_input})
        st.session_state.generate_response = True
        st.rerun()




