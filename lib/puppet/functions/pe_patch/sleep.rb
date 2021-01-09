# Adapted from puppetlabs-reboot
Puppet::Functions.create_function('pe_patch::sleep') do
  dispatch :sleeper do
    required_param 'Integer', :period
  end

  def sleeper(period)
    sleep(period)
  end
end