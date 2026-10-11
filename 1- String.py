- id: failed_login_bruteforce
  description: "More than 10 failed logins for same user within 1 hour"
  type: aggregate
  agg_op: count
  agg_field: event  # any field; we use 1 if missing
  group_by: ["user_id"]
  window_seconds: 3600
  threshold: 10
  severity: high

- id: data_exfil_pattern
  description: "Large file download to external IP"
  type: match
  condition: "event == 'file_download' and bytes > 100000000 and not (destination_ip.startswith('10.') or destination_ip.startswith('192.168.'))"
  severity: critical

- id: suspicious_user_agent
  description: "Known bad UA regex"
  type: match
  condition: "re_match('^curl/|^wget/|sqlmap', user_agent)"
  severity: medium
