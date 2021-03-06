control 'V-76813' do
  title "The IIS 8.5 website must generate unique session identifiers that
  cannot be reliably reproduced."
  desc "Communication between a client and the web server is done using the
  HTTP protocol, but HTTP is a stateless protocol. In order to maintain a
  connection or session, a web server will generate a session identifier (ID) for
  each client session when the session is initiated. The session ID allows the
  web server to track a user session and, in many cases, the user, if the user
  previously logged into a hosted application.

      By being able to guess session IDs, an attacker can easily perform a
  man-in-the-middle attack. To truly generate random session identifiers that
  cannot be reproduced, the web server session ID generator, when used twice with
  the same input criteria, must generate an unrelated random ID.

    The session ID generator also needs to be a FIPS 140-2-approved generator.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000224-WSR-000136'
  tag "gid": 'V-76813'
  tag "rid": 'SV-91509r1_rule'
  tag "stig_id": 'IISW-SI-000223'
  tag "fix_id": 'F-83509r1_fix'
  tag "cci": ['CCI-001188']
  tag "nist": ['SC-23 (3)', 'Rev_4']
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
  tag "check": "Follow the procedures below for each site hosted on the IIS 8.5
  web server:

  Open the IIS 8.5 Manager.

  Click the site name.

  Under the \"ASP.NET\" section, select \"Session State\".

  Under \"Session State\" Mode Settings, verify the \"In Process\" mode is
  selected.

  If the \"In Process\" mode is selected, this is not a finding.

  Alternative method:

  Click the site name.

  Select \"Configuration Editor\" under the \"Management\" section.

  From the \"Section:\" drop-down list at the top of the configuration editor,
  locate \"system.web/sessionState\".

  Verify the \"mode\" reflects \"InProc\".

  If the \"mode\" is not set to \"InProc\", this is a finding."
  tag "fix": "Follow the procedures below for each site hosted on the IIS 8.5
  web server:

  Open the IIS 8.5 Manager.

  Click the site name.

  Under the ASP.NET section, select \"Session State\".

  Under \"Session State\" Mode Settings, select the \"In Process\" mode."
  get_mode = command('Get-WebConfigurationProperty -Filter system.web/sessionState -pspath "IIS:\Sites\*" -name * | select -expand mode').stdout.strip.split("\r\n")
  get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")

  get_mode.zip(get_names).each do |mode, names|
    describe "The IIS site: #{names} website session state" do
      subject { mode }
      it { should eq 'InProc' }
    end
  end
  if get_names.empty?
    impact 0.0
    desc 'There are no IIS sites configured hence the control is Not-Applicable'

    describe 'No sites where found to be reviewed' do
      skip 'No sites where found to be reviewed'
    end
  end
end
