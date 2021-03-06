control 'V-76837' do
  title "Debugging and trace information used to diagnose the IIS 8.5 website
  must be disabled."
  desc "Setting compilation debug to false ensures detailed error information
  does not inadvertently display during live application usage, mitigating the
  risk of application information being displayed to users."
  impact 0.5
  tag "gtitle": 'SRG-APP-000266-WSR-000160'
  tag "gid": 'V-76837'
  tag "rid": 'SV-91533r1_rule'
  tag "stig_id": 'IISW-SI-000234'
  tag "fix_id": 'F-83533r1_fix'
  tag "cci": ['CCI-001312']
  tag "nist": ['SI-11 a', 'Rev_4']
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
  tag "check": "Note: If the \".NET feature\" is not installed, this check is
  Not Applicable.

  Follow the procedures below for each site hosted on the IIS 8.5 web server:

  Open the IIS 8.5 Manager.

  Click the site name under review.

  Double-click \".NET Compilation\".

  Scroll down to the \"Behavior\" section and verify the value for \"Debug\" is
  set to \"False\".

  If the \"Debug\" value is not set to \"False\", this is a finding."
  tag "fix": "Follow the procedures below for each site hosted on the IIS 8.5
  web server:

  Open the IIS 8.5 Manager.

  Click the site name under review.

  Double-click \".NET Compilation\".

  Scroll down to the \"Behavior\" section and set the value for \"Debug\" to
  \"False\"."

  get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")
  get_debug_enabled = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" -Filter system.web/compilation -name * | select -expand debug').stdout.strip.split("\r\n")

  get_debug_enabled.zip(get_names).each do |debug_enabled, names|
    n = names.strip

    describe "The IIS site: #{n} websites debugging enabled" do
      subject { debug_enabled }
      it { should cmp 'False' }
    end
  end

  iis_modules = command('Get-WebConfiguration  system.webServer/globalModules/*').stdout.strip

  unless iis_modules.include?('.NET')
    impact 0.0
    desc '.NET feature not installed hence the control not applicable'
  end

  if get_names.empty?
    impact 0.0
    desc 'There are no IIS sites configured hence the control is Not-Applicable'

    describe 'No sites where found to be reviewed' do
      skip 'No sites where found to be reviewed'
    end
  end
end
