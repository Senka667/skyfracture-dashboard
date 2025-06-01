import streamlit as st
import pandas as pd
import numpy as np
import time
import random
import yaml
import os
import json
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from collections import Counter

# Set page configuration
st.set_page_config(
    page_title="SKYFRACTURE™ Security Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply custom CSS
st.markdown("""
<style>
    .main {
        background-color: #0e1117;
    }
    .st-emotion-cache-16txtl3 h1 {
        color: #f63366;
    }
    .st-emotion-cache-16txtl3 h2 {
        color: #4da6ff;
    }
    .st-emotion-cache-16txtl3 h3 {
        color: #00cc96;
    }
    .critical {
        color: #ff4b4b;
        font-weight: bold;
    }
    .high {
        color: #ff9d00;
        font-weight: bold;
    }
    .medium {
        color: #ffcc00;
    }
    .low {
        color: #00cc96;
    }
    .dashboard-title {
        text-align: center;
        margin-bottom: 20px;
    }
    .metric-card {
        background-color: #1e2130;
        border-radius: 5px;
        padding: 15px;
        margin: 5px;
    }
    .alert-card {
        background-color: #1e2130;
        border-radius: 5px;
        padding: 10px;
        margin-bottom: 10px;
        border-left: 4px solid #ff4b4b;
    }
    .event-card {
        background-color: #1e2130;
        border-radius: 5px;
        padding: 10px;
        margin-bottom: 10px;
        border-left: 4px solid #4da6ff;
    }
    .anomaly-card {
        background-color: #1e2130;
        border-radius: 5px;
        padding: 10px;
        margin-bottom: 10px;
        border-left: 4px solid #ff9d00;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'events' not in st.session_state:
    st.session_state.events = []
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'fracture_scores' not in st.session_state:
    st.session_state.fracture_scores = []
if 'detection_packs' not in st.session_state:
    st.session_state.detection_packs = []
if 'simulation_running' not in st.session_state:
    st.session_state.simulation_running = False
if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now()
if 'current_fracture_score' not in st.session_state:
    st.session_state.current_fracture_score = 0.0
if 'total_events' not in st.session_state:
    st.session_state.total_events = 0
if 'total_alerts' not in st.session_state:
    st.session_state.total_alerts = 0
if 'alert_by_pattern' not in st.session_state:
    st.session_state.alert_by_pattern = {}
if 'events_by_user' not in st.session_state:
    st.session_state.events_by_user = {}
if 'events_by_type' not in st.session_state:
    st.session_state.events_by_type = {}
if 'events_by_location' not in st.session_state:
    st.session_state.events_by_location = {}

# Constants for simulation
USERS = [
    {"user_id": "alice", "normal_location": "New York", "role": "user"},
    {"user_id": "bob", "normal_location": "Chicago", "role": "user"},
    {"user_id": "charlie", "normal_location": "San Francisco", "role": "admin"},
    {"user_id": "dave", "normal_location": "Boston", "role": "user"},
    {"user_id": "eve", "normal_location": "London", "role": "executive"},
]

LOCATIONS = ["New York", "Chicago", "San Francisco", "Boston", "London", "Beijing", "Tokyo", "Sydney"]
EVENT_TYPES = [
    "successful_login",
    "failed_login",
    "admin_access",
    "file_access",
    "vpn_connection",
    "database_query",
    "config_change",
    "data_export"
]

# Function to load detection packs
def load_detection_packs(directory_or_file):
    """Load detection packs from a directory or a single YAML file."""
    packs = []
    if os.path.isdir(directory_or_file):
        for file in os.listdir(directory_or_file):
            if file.endswith('.yaml') or file.endswith('.yml'):
                try:
                    with open(os.path.join(directory_or_file, file), 'r') as f:
                        pack = yaml.safe_load(f)
                        packs.append(pack)
                except Exception as e:
                    st.error(f"Error loading detection pack {file}: {e}")
    elif os.path.isfile(directory_or_file) and (directory_or_file.endswith('.yaml') or directory_or_file.endswith('.yml')):
        try:
            with open(directory_or_file, 'r') as f:
                pack = yaml.safe_load(f)
                packs.append(pack)
        except Exception as e:
            st.error(f"Error loading detection pack {directory_or_file}: {e}")
    return packs

# Function to check if a pattern matches an event
def pattern_matches(event, pattern):
    # Simplified pattern matching for demo
    for cond in pattern.get('conditions', []):
        if cond['type'] == "time_window":
            hour = event['hour']
            start, end = [int(t.split(":")[0]) for t in cond['not_between']]
            if start <= hour <= end:
                return False  # Not after hours
        if cond['type'] == "geo_location":
            if event['location'] in cond.get('not_in_locations', []):
                return False
        if cond['type'] == "ip_range":
            if event['ip_address'].startswith('10.') or event['ip_address'].startswith('192.168.'):
                return False
        if cond['type'] == "role_check":
            if event['role'] not in cond.get('roles', []):
                return False
    return True  # All conditions pass

# Function to find matching pattern
def find_matching_pattern(event, patterns):
    for pattern in patterns:
        if pattern_matches(event, pattern):
            return pattern
    return None

# Function to generate a simulated security event
def generate_security_event(patterns):
    user = random.choice(USERS)
    location = random.choice(LOCATIONS)
    hour = random.randint(0, 23)
    event_type = random.choice(EVENT_TYPES)
    ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}" \
        if random.random() < 0.7 else f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

    base_score = 0.1 + 0.4 * (event_type in ["admin_access", "vpn_connection", "data_export"])
    matched_pattern = None
    recommendations = []
    score = base_score
    severity = "low"

    # Pattern matching
    pattern = find_matching_pattern(
        {
            "hour": hour,
            "location": location,
            "ip_address": ip,
            "event_type": event_type,
            "role": user["role"]
        }, patterns
    )
    
    if pattern:
        matched_pattern = pattern["name"]
        score += pattern.get("score_modifier", 0.6)
        recommendations = pattern.get("recommended_actions", [])
        severity = pattern.get("severity", "medium")

    # Clamp score
    score = min(score, 1.0)
    
    event = {
        "event_id": st.session_state.total_events + 1,
        "timestamp": datetime.now(),
        "user_id": user["user_id"],
        "event_type": event_type,
        "location": location,
        "ip_address": ip,
        "hour": hour,
        "role": user["role"],
        "score": round(score, 3),
        "matched_pattern": matched_pattern,
        "recommendations": recommendations,
        "severity": severity
    }
    
    st.session_state.total_events += 1
    
    # Update statistics
    if user["user_id"] in st.session_state.events_by_user:
        st.session_state.events_by_user[user["user_id"]] += 1
    else:
        st.session_state.events_by_user[user["user_id"]] = 1
        
    if event_type in st.session_state.events_by_type:
        st.session_state.events_by_type[event_type] += 1
    else:
        st.session_state.events_by_type[event_type] = 1
        
    if location in st.session_state.events_by_location:
        st.session_state.events_by_location[location] += 1
    else:
        st.session_state.events_by_location[location] = 1
    
    # Create alert if score is high enough
    if score > 0.7:
        alert = event.copy()
        st.session_state.alerts.insert(0, alert)
        st.session_state.total_alerts += 1
        
        # Update alert by pattern stats
        if matched_pattern:
            if matched_pattern in st.session_state.alert_by_pattern:
                st.session_state.alert_by_pattern[matched_pattern] += 1
            else:
                st.session_state.alert_by_pattern[matched_pattern] = 1
    
    # Update fracture score (moving average)
    st.session_state.current_fracture_score = 0.7 * st.session_state.current_fracture_score + 0.3 * score
    st.session_state.fracture_scores.append({
        "timestamp": datetime.now(),
        "score": st.session_state.current_fracture_score
    })
    
    # Keep only the last 100 events and scores for performance
    st.session_state.events.insert(0, event)
    if len(st.session_state.events) > 100:
        st.session_state.events = st.session_state.events[:100]
    if len(st.session_state.alerts) > 50:
        st.session_state.alerts = st.session_state.alerts[:50]
    if len(st.session_state.fracture_scores) > 100:
        st.session_state.fracture_scores = st.session_state.fracture_scores[-100:]
    
    st.session_state.last_update = datetime.now()
    return event

# Function to start simulation
def start_simulation():
    st.session_state.simulation_running = True

# Function to stop simulation
def stop_simulation():
    st.session_state.simulation_running = False

# Function to reset simulation
def reset_simulation():
    st.session_state.events = []
    st.session_state.alerts = []
    st.session_state.fracture_scores = []
    st.session_state.simulation_running = False
    st.session_state.last_update = datetime.now()
    st.session_state.current_fracture_score = 0.0
    st.session_state.total_events = 0
    st.session_state.total_alerts = 0
    st.session_state.alert_by_pattern = {}
    st.session_state.events_by_user = {}
    st.session_state.events_by_type = {}
    st.session_state.events_by_location = {}

# Sidebar
with st.sidebar:
    st.image("https://via.placeholder.com/150x50?text=SKYFRACTURE", width=150)
    st.title("Control Panel")
    
    # Detection pack selection
    st.subheader("Detection Packs")
    detection_pack_path = st.text_input("Detection Pack Path", value="./detection_packs/")
    
    if st.button("Load Detection Packs"):
        packs = load_detection_packs(detection_pack_path)
        if packs:
            st.session_state.detection_packs = packs
            all_patterns = []
            for pack in packs:
                all_patterns.extend(pack.get("patterns", []))
            st.session_state.all_patterns = all_patterns
            st.success(f"Loaded {len(packs)} detection packs with {len(all_patterns)} patterns")
        else:
            st.error("No detection packs found at the specified path")
    
    # Simulation controls
    st.subheader("Simulation Controls")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Start Simulation", disabled=st.session_state.simulation_running):
            start_simulation()
    with col2:
        if st.button("Stop Simulation", disabled=not st.session_state.simulation_running):
            stop_simulation()
    
    if st.button("Reset Simulation"):
        reset_simulation()
    
    # Simulation speed
    simulation_speed = st.slider("Simulation Speed", min_value=0.1, max_value=5.0, value=1.0, step=0.1)
    
    # Display stats
    st.subheader("Statistics")
    st.metric("Total Events", st.session_state.total_events)
    st.metric("Total Alerts", st.session_state.total_alerts)
    st.metric("Current Fracture Score", f"{st.session_state.current_fracture_score:.3f}")
    st.text(f"Last Update: {st.session_state.last_update.strftime('%H:%M:%S')}")

# Main dashboard
st.markdown("<h1 class='dashboard-title'>SKYFRACTURE™ Enterprise Security Dashboard</h1>", unsafe_allow_html=True)

# Top metrics row
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
    st.metric("Fracture Score", f"{st.session_state.current_fracture_score:.3f}")
    st.markdown("</div>", unsafe_allow_html=True)
with col2:
    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
    st.metric("Active Alerts", len(st.session_state.alerts))
    st.markdown("</div>", unsafe_allow_html=True)
with col3:
    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
    st.metric("Events Today", st.session_state.total_events)
    st.markdown("</div>", unsafe_allow_html=True)
with col4:
    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
    st.metric("Detection Patterns", len(st.session_state.all_patterns) if hasattr(st.session_state, 'all_patterns') else 0)
    st.markdown("</div>", unsafe_allow_html=True)

# Main content
col1, col2 = st.columns([2, 1])

with col1:
    # Fracture Score Chart
    st.subheader("Fracture Score Trend")
    if st.session_state.fracture_scores:
        df_scores = pd.DataFrame([
            {"timestamp": score["timestamp"], "score": score["score"]} 
            for score in st.session_state.fracture_scores
        ])
        
        fig = px.line(
            df_scores, 
            x="timestamp", 
            y="score", 
            title="System Fracture Score Over Time",
            labels={"timestamp": "Time", "score": "Fracture Score"},
            line_shape="spline"
        )
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Fracture Score",
            yaxis_range=[0, 1],
            plot_bgcolor="#1e2130",
            paper_bgcolor="#1e2130",
            font=dict(color="#ffffff"),
            margin=dict(l=20, r=20, t=30, b=20),
        )
        fig.add_shape(
            type="line",
            x0=df_scores["timestamp"].min(),
            x1=df_scores["timestamp"].max(),
            y0=0.7,
            y1=0.7,
            line=dict(color="red", width=2, dash="dash"),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data available yet. Start the simulation to see the fracture score trend.")
    
    # Event Distribution Charts
    st.subheader("Event Distribution")
    
    tab1, tab2, tab3 = st.tabs(["By User", "By Event Type", "By Location"])
    
    with tab1:
        if st.session_state.events_by_user:
            df_users = pd.DataFrame([
                {"user": user, "events": count} 
                for user, count in st.session_state.events_by_user.items()
            ])
            fig = px.bar(
                df_users, 
                x="user", 
                y="events", 
                title="Events by User",
                color="events",
                color_continuous_scale="Viridis"
            )
            fig.update_layout(
                xaxis_title="User",
                yaxis_title="Event Count",
                plot_bgcolor="#1e2130",
                paper_bgcolor="#1e2130",
                font=dict(color="#ffffff"),
                margin=dict(l=20, r=20, t=30, b=20),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No user data available yet.")
    
    with tab2:
        if st.session_state.events_by_type:
            df_types = pd.DataFrame([
                {"type": event_type, "events": count} 
                for event_type, count in st.session_state.events_by_type.items()
            ])
            fig = px.pie(
                df_types, 
                values="events", 
                names="type", 
                title="Events by Type",
                hole=0.4,
                color_discrete_sequence=px.colors.sequential.Viridis
            )
            fig.update_layout(
                plot_bgcolor="#1e2130",
                paper_bgcolor="#1e2130",
                font=dict(color="#ffffff"),
                margin=dict(l=20, r=20, t=30, b=20),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No event type data available yet.")
    
    with tab3:
        if st.session_state.events_by_location:
            df_locations = pd.DataFrame([
                {"location": location, "events": count} 
                for location, count in st.session_state.events_by_location.items()
            ])
            fig = px.bar(
                df_locations, 
                x="location", 
                y="events", 
                title="Events by Location",
                color="events",
                color_continuous_scale="Viridis"
            )
            fig.update_layout(
                xaxis_title="Location",
                yaxis_title="Event Count",
                plot_bgcolor="#1e2130",
                paper_bgcolor="#1e2130",
                font=dict(color="#ffffff"),
                margin=dict(l=20, r=20, t=30, b=20),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No location data available yet.")

with col2:
    # Active Alerts
    st.subheader("Active Alerts")
    if st.session_state.alerts:
        for alert in st.session_state.alerts[:10]:  # Show only top 10 alerts
            severity_class = alert.get("severity", "medium").lower()
            st.markdown(f"""
            <div class='alert-card'>
                <span class='{severity_class}'>{alert.get("severity", "Medium").upper()}</span>: {alert.get("matched_pattern", "Unknown Pattern")}
                <br><strong>User:</strong> {alert.get("user_id")} | <strong>Type:</strong> {alert.get("event_type")}
                <br><strong>Location:</strong> {alert.get("location")} | <strong>Score:</strong> {alert.get("score")}
                <br><strong>Time:</strong> {alert.get("timestamp").strftime('%H:%M:%S')}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No active alerts.")
    
    # Top Detection Patterns
    st.subheader("Top Detection Patterns")
    if st.session_state.alert_by_pattern:
        df_patterns = pd.DataFrame([
            {"pattern": pattern, "alerts": count} 
            for pattern, count in st.session_state.alert_by_pattern.items()
        ]).sort_values("alerts", ascending=False)
        
        fig = px.bar(
            df_patterns, 
            x="pattern", 
            y="alerts", 
            title="Alerts by Pattern",
            color="alerts",
            color_continuous_scale="Reds"
        )
        fig.update_layout(
            xaxis_title="Pattern",
            yaxis_title="Alert Count",
            plot_bgcolor="#1e2130",
            paper_bgcolor="#1e2130",
            font=dict(color="#ffffff"),
            margin=dict(l=20, r=20, t=30, b=20),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No pattern data available yet.")
    
    # Recent Events
    st.subheader("Recent Events")
    if st.session_state.events:
        for event in st.session_state.events[:5]:  # Show only top 5 events
            if event.get("matched_pattern"):
                st.markdown(f"""
                <div class='anomaly-card'>
                    <strong>{event.get("event_type")}</strong> by {event.get("user_id")} ({event.get("role")})
                    <br><strong>Pattern:</strong> {event.get("matched_pattern")}
                    <br><strong>Score:</strong> {event.get("score")} | <strong>Location:</strong> {event.get("location")}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class='event-card'>
                    <strong>{event.get("event_type")}</strong> by {event.get("user_id")} ({event.get("role")})
                    <br><strong>Score:</strong> {event.get("score")} | <strong>Location:</strong> {event.get("location")}
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No events recorded yet.")

# Run simulation if active
if st.session_state.simulation_running and hasattr(st.session_state, 'all_patterns'):
    event = generate_security_event(st.session_state.all_patterns)
    time.sleep(1.0 / simulation_speed)
    st.rerun()  # Use st.rerun() instead of st.experimental_rerun()

# Footer
st.markdown("---")
st.markdown("<p style='text-align: center'>SKYFRACTURE™ Enterprise Security Edition | © 2025</p>", unsafe_allow_html=True)
