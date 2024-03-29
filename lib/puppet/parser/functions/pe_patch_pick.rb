# frozen_string_literal: true

# From Stdlib's pick function
# Disabling rubocop issues in order to stay as close as possible to the stdlib function.
# rubocop:disable Style/HashSyntax, GetText/DecorateFunctionMessage

module Puppet::Parser::Functions
  newfunction(:pe_patch_pick, :type => :rvalue, :doc => <<-EOS
    @summary
      This function is similar to a coalesce function in SQL in that it will return
      the first value in a list of values that is not undefined or an empty string.
    @return
      the first value in a list of values that is not undefined or an empty string.
    Typically, this function is used to check for a value in the Puppet
    Dashboard/Enterprise Console, and failover to a default value like the following:
    ```$real_jenkins_version = pe_patch_pick($::jenkins_version, '1.449')```
    > *Note:*
      The value of $real_jenkins_version will first look for a top-scope variable
      called 'jenkins_version' (note that parameters set in the Puppet Dashboard/
      Enterprise Console are brought into Puppet as top-scope variables), and,
      failing that, will use a default value of 1.449.
  EOS
             ) do |args|
    args = args.compact
    args.delete(:undef)
    args.delete(:undefined)
    args.delete('')
    raise Puppet::ParseError, 'pe_patch_pick(): must receive at least one non empty value' if args[0].to_s.empty?
    return args[0]
  end
end
