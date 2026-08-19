
# AUTOMATED THREAT HUNTING

from google.colab import files
uploaded = files.upload()

import pandas as pd

pd.set_option('display.max_columns', None)
pd.set_option('display.max_colwidth', 80)
pd.set_option('display.width', 200)
# Convert timestamp for time-based analysis
df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')

# FINDING 1: Suspicious Post-Login Activity
# Suspicious command indicators observed during investigation
suspicious_patterns = r'/dev/tcp|nohup|/tmp|dd\s'
finding1 = df[
    (df['event_type'] == 'exec_command') &
    (
        df['command'].fillna('').str.contains(
            suspicious_patterns,
            case=False,
            regex=True
        )
        |
        df['message'].fillna('').str.contains(
            suspicious_patterns,
            case=False,
            regex=True
        )
    )
].copy()
print("=== FINDING 1: SUSPICIOUS POST-LOGIN ACTIVITY ===")
display(
    finding1[
        ['timestamp', 'session_id', 'ip',
         'event_type', 'message', 'command', 'level']
    ].sort_values('timestamp')
)

# FINDING 2: High-Volume and Rapid SSH Activity
ssh_events = df[
    df['event_type'].isin(['SSH connect', 'SSH login'])
].copy()
# Count SSH connection/login events per source IP
finding2_summary = (
    ssh_events.groupby('ip')
    .size()
    .reset_index(name='event_count')
)
# First and last observed activity
time_summary = (
    ssh_events.groupby('ip')['datetime']
    .agg(['min', 'max'])
    .reset_index()
    .rename(columns={
        'min': 'first_seen',
        'max': 'last_seen'
    })
)
finding2_summary = finding2_summary.merge(
    time_summary,
    on='ip'
)

# Automatically flag high-volume sources
finding2_summary = (
    finding2_summary[
        finding2_summary['event_count'] >= 100
    ]
    .sort_values('event_count', ascending=False)
    .head(10)
    .reset_index(drop=True)
)
print("\n=== FINDING 2: HIGH-VOLUME AND RAPID SSH ACTIVITY ===")
display(finding2_summary)
# Show detailed events for the highest-volume IP
if not finding2_summary.empty:
    top_ip = finding2_summary.iloc[0]['ip']
    finding2_details = ssh_events[
        ssh_events['ip'] == top_ip
    ][
        ['timestamp', 'ip', 'event_type', 'message']
    ].sort_values('timestamp').head(20)
    print(f"\n=== Detailed Activity for Top IP: {top_ip} ===")
    display(finding2_details)

# FINDING 3: Repeated Credential Attempts
login_events = df[
    df['event_type'] == 'SSH login'
].copy()
# Extract username/password combination
login_events['credentials'] = login_events['message'].str.extract(
    r'(username:\s*.*?,\s*password:\s*.*)'
)[0]
# Count repeated credentials
credential_counts = (
    login_events.groupby('credentials')
    .size()
    .reset_index(name='attempt_count')
)
# Count different source IPs for each credential pair
credential_ip_counts = (
    login_events.groupby('credentials')['ip']
    .nunique()
    .reset_index(name='source_ip_count')
)
finding3_summary = credential_counts.merge(
    credential_ip_counts,
    on='credentials'
)
# Automatically flag credentials repeatedly attempted
# from multiple source IPs
finding3_summary = (
    finding3_summary[
        (finding3_summary['attempt_count'] >= 20) &
        (finding3_summary['source_ip_count'] >= 2)
    ]
    .sort_values(
        ['attempt_count', 'source_ip_count'],
        ascending=False
    )
    .head(10)
    .reset_index(drop=True)
)
print("\n=== FINDING 3: REPEATED CREDENTIAL ATTEMPTS ===")
display(finding3_summary)
# Show detailed events for the most frequently attempted credential
if not finding3_summary.empty:
    top_credential = finding3_summary.iloc[0]['credentials']
    finding3_details = login_events[
        login_events['credentials'] == top_credential
    ][
        ['timestamp', 'ip', 'message', 'level']
    ].head(20)
    print("\n=== Detailed Attempts for Top Credential Pair ===")
    display(finding3_details)

# FINDING 4: Off-Peak Automated SSH Credential-Guessing
# Select SSH activity between 00:00 and 06:00
off_peak_ssh = df[
    (df['datetime'].dt.hour >= 0) &
    (df['datetime'].dt.hour <= 6) &
    (df['event_type'].isin(['SSH connect', 'SSH login']))
].copy()
# Total off-peak SSH activity per IP
off_peak_counts = (
    off_peak_ssh.groupby('ip')
    .size()
    .reset_index(name='off_peak_events')
)
# WARNING-level SSH login activity
warning_logins = off_peak_ssh[
    (off_peak_ssh['event_type'] == 'SSH login') &
    (off_peak_ssh['level'] == 'WARNING')
].copy()
warning_counts = (
    warning_logins.groupby('ip')
    .size()
    .reset_index(name='warning_login_events')
)
finding4_summary = off_peak_counts.merge(
    warning_counts,
    on='ip',
    how='left'
)
finding4_summary['warning_login_events'] = (
    finding4_summary['warning_login_events']
    .fillna(0)
)
# Automatically flag IPs with repeated off-peak
# WARNING-level login activity
finding4_summary = (
    finding4_summary[
        (finding4_summary['warning_login_events'] > 0) &
        (finding4_summary['off_peak_events'] >= 10)
    ]
    .sort_values(
        ['warning_login_events', 'off_peak_events'],
        ascending=False
    )
    .head(10)
    .reset_index(drop=True)
)
print(
    "\n=== FINDING 4: OFF-PEAK AUTOMATED "
    "SSH CREDENTIAL-GUESSING ACTIVITY ==="
)
display(finding4_summary)
# Show detailed WARNING/Bot evidence for the strongest IP
if not finding4_summary.empty:
    top_off_peak_ip = finding4_summary.iloc[0]['ip']
    finding4_details = off_peak_ssh[
        off_peak_ssh['ip'] == top_off_peak_ip
    ][
        ['timestamp', 'ip', 'event_type', 'level', 'message']
    ].sort_values('timestamp')
    finding4_details = finding4_details[
        (finding4_details['level'] == 'WARNING') |
        (finding4_details['message'].str.contains(
            'bot',
            case=False,
            na=False
        ))
    ].head(20)
    print(
        f"\n=== WARNING / BOT ACTIVITY: "
        f"{top_off_peak_ip} ==="
    )
    display(finding4_details)

# AUTOMATION SUMMARY
print("\n" + "=" * 70)
print("AUTOMATED THREAT HUNTING SUMMARY")
print("=" * 70)
print(
    f"Finding 1 - Suspicious Post-Login Activity: "
    f"{len(finding1)} events flagged"
)
print(
    f"Finding 2 - High-Volume and Rapid SSH Activity: "
    f"{len(finding2_summary)} IPs flagged"
)
print(
    f"Finding 3 - Repeated Credential Attempts: "
    f"{len(finding3_summary)} credential patterns flagged"
)
print(
    f"Finding 4 - Off-Peak Automated SSH Activity: "
    f"{len(finding4_summary)} IPs flagged"
)