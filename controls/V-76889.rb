control 'V-76889' do
  title 'Backup interactive scripts on the IIS 8.5 server must be removed.'
  desc  "Copies of backup files will not execute on the server, but they can be
  read by the anonymous user if special precautions are not taken. Such backup
  copies contain the same sensitive information as the actual script being
  executed and, as such, are useful to malicious users. Techniques and systems
  exist today to search web servers for such files and are able to exploit the
  information contained in them."
  impact 0.5
  tag "gtitle": 'SRG-APP-000141-WSR-000087'
  tag "gid": 'V-76889'
  tag "rid": 'SV-91585r1_rule'
  tag "stig_id": 'IISW-SI-000263'
  tag "fix_id": 'F-83585r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
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
  tag "check": "Determine whether scripts are used on the web server for the
  subject website. Common file extensions include, but are not limited to: .cgi,
  .pl, .vb, .class, .c, .php, .asp, and .aspx.

  If the website does not utilize CGI, this finding is Not Applicable.

  Open the IIS 8.5 Manager.

  Right-click the IIS 8.5 web site name and select Explore.

  Search for the listed script extensions

  Search for the following files: *.bak, *.old, *.temp, *.tmp, *.backup, or copy
  of....

  If files with these extensions are found, this is a finding."
  tag "fix": 'Remove the backup files from the production web server.'

  iis_modules = command('Get-WebConfiguration  system.webServer/globalModules/*').stdout.strip

  unless iis_modules.include?('CgiModule')
    impact 0.0
    desc 'CgiModule not installed hence the control not applicable'
  end

  describe 'Manual review of website is needed' do
    skip 'Manual review that Backup interactive scripts on the IIS 8.5 server is removed'
  end
end
