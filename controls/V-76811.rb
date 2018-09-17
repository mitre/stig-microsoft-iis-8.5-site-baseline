control "V-76811" do
  title "Anonymous IIS 8.5 website access accounts must be restricted."
  desc  "Many of the security problems that occur are not the result of a user
gaining access to files or data for which the user does not have permissions,
but rather users are assigned incorrect permissions to unauthorized data. The
files, directories, and data that are stored on the web server need to be
evaluated and a determination made concerning authorized access to information
and programs on the server. Only authorized users and administrative accounts
will be allowed on the host server in order to maintain the web server,
applications, and review the server operations."
  impact 0.7
  tag "gtitle": "SRG-APP-000211-WSR-000031"
  tag "gid": "V-76811"
  tag "rid": "SV-91507r1_rule"
  tag "stig_id": "IISW-SI-000221"
  tag "fix_id": "F-83507r1_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Check the account used for anonymous access to the website.

Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Double-click \"Authentication\" in the IIS section of the website’s Home Pane.

If Anonymous access is disabled, this is Not a Finding.

If enabled, click “Anonymous Authentication” and then click “Edit” in the
\"Actions\" pane.

If the “Specific user” radio button is enabled and an ID is specified in the
adjacent control box, this is the ID being used for anonymous access.

Check privileged groups that may allow the anonymous account inappropriate
membership.

Click “Start” and then double-click “Server Manager”.

Expand Configuration; expand Local Users and Groups; and then click “Groups”.

Review group members.

Privileged Groups:
Administrators
Backup Operators
Certificate Services (of any designation)
Distributed COM Users
Event Log Readers
Network Configuration Operators
Performance Log Users
Performance Monitor Users
Power Users
Print Operators
Remote Desktop Users
Replicator
Users

Double-click each group and review its members.

If the IUSR account or any account used for anonymous access is a member of any
group with privileged access, this is a finding."
  tag "fix": "Remove the Anonymous access account from all privileged accounts
and all privileged groups."
end
