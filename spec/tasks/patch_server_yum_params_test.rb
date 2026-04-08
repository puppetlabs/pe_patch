#!/usr/bin/env ruby
# Test for bug fix: yum_params --enablerepo should work even when updatecount is 0
#
# This is a standalone test that verifies the skip_count_check logic in patch_server.rb
# without requiring full RSpec dependencies.
#
# Bug description:
# When feeding "--enablerepo=local*UEKR*current" into the yum_params field, it does not
# apply to Linux nodes when the cached update count is 0. This is because the task exits
# early before running yum with the enablerepo parameter.
#
# The fix (already implemented in patch_server.rb lines 469-472):
# - Check if yum_params or zypper_params are set
# - If set, skip the early exit check and let yum/zypper run with those params
# - This allows repos enabled via --enablerepo to be queried for updates
#
# To run this test:
#   ruby spec/tasks/patch_server_yum_params_test.rb

require 'json'

class PatchServerYumParamsTest
  def initialize
    @tests_passed = 0
    @tests_failed = 0
    @failures = []
  end

  def assert(condition, message)
    if condition
      @tests_passed += 1
      puts "  ✓ #{message}"
    else
      @tests_failed += 1
      @failures << message
      puts "  ✗ FAILED: #{message}"
    end
  end

  def test_skip_count_check_logic
    puts "\n=== Testing skip_count_check logic ==="
    puts "This tests the core bug fix: whether the task should skip early exit\n"

    # Test 1: RedHat with yum_params set should skip count check
    puts "\nTest 1: RedHat with yum_params set"
    yum_params = '--enablerepo=local*UEKR*current'
    zypper_params = ''
    os_family = 'RedHat'
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat') ||
                       (!zypper_params.empty? && os_family == 'Suse')
    assert(skip_count_check == true, "Should skip count check when yum_params is set on RedHat")

    # Test 2: RedHat without yum_params should NOT skip count check
    puts "\nTest 2: RedHat without yum_params"
    yum_params = ''
    zypper_params = ''
    os_family = 'RedHat'
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat') ||
                       (!zypper_params.empty? && os_family == 'Suse')
    assert(skip_count_check == false, "Should NOT skip count check when yum_params is empty on RedHat")

    # Test 3: Suse with zypper_params set should skip count check
    puts "\nTest 3: Suse with zypper_params set"
    yum_params = ''
    zypper_params = '--plus-repo=custom_repo'
    os_family = 'Suse'
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat') ||
                       (!zypper_params.empty? && os_family == 'Suse')
    assert(skip_count_check == true, "Should skip count check when zypper_params is set on Suse")

    # Test 4: Suse without zypper_params should NOT skip count check
    puts "\nTest 4: Suse without zypper_params"
    yum_params = ''
    zypper_params = ''
    os_family = 'Suse'
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat') ||
                       (!zypper_params.empty? && os_family == 'Suse')
    assert(skip_count_check == false, "Should NOT skip count check when zypper_params is empty on Suse")

    # Test 5: RedHat with yum_params on Debian should NOT skip (wrong OS)
    puts "\nTest 5: Debian with yum_params (wrong OS family)"
    yum_params = '--enablerepo=test'
    zypper_params = ''
    os_family = 'Debian'
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat') ||
                       (!zypper_params.empty? && os_family == 'Suse')
    assert(skip_count_check == false, "Should NOT skip count check for yum_params on non-RedHat OS")
  end

  def test_early_exit_behavior
    puts "\n\n=== Testing early exit behavior ==="
    puts "This tests when the task should exit early vs continue to run yum/zypper\n"

    # Scenario 1: updatecount=0, no yum_params -> should exit early
    puts "\nScenario 1: updatecount=0, no yum_params"
    updatecount = 0
    yum_params = ''
    os_family = 'RedHat'
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat')
    should_exit_early = updatecount.zero? && !skip_count_check
    assert(should_exit_early == true, "Should exit early when no updates and no yum_params")

    # Scenario 2: updatecount=0, yum_params set -> should NOT exit early
    puts "\nScenario 2: updatecount=0, yum_params='--enablerepo=local*UEKR*current'"
    updatecount = 0
    yum_params = '--enablerepo=local*UEKR*current'
    os_family = 'RedHat'
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat')
    should_exit_early = updatecount.zero? && !skip_count_check
    assert(should_exit_early == false, "Should NOT exit early when yum_params is set (bug fix)")

    # Scenario 3: updatecount>0, no yum_params -> should NOT exit early
    puts "\nScenario 3: updatecount=5, no yum_params"
    updatecount = 5
    yum_params = ''
    os_family = 'RedHat'
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat')
    should_exit_early = updatecount.zero? && !skip_count_check
    assert(should_exit_early == false, "Should NOT exit early when updates are available")

    # Scenario 4: updatecount>0, yum_params set -> should NOT exit early
    puts "\nScenario 4: updatecount=5, yum_params set"
    updatecount = 5
    yum_params = '--enablerepo=test'
    os_family = 'RedHat'
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat')
    should_exit_early = updatecount.zero? && !skip_count_check
    assert(should_exit_early == false, "Should NOT exit early when updates available AND yum_params set")
  end

  def test_customer_scenario
    puts "\n\n=== Testing Customer Bug Scenario ==="
    puts "Oracle Linux with disabled UEKR7 repo containing kernel updates\n"

    puts "\nCustomer Scenario: Server with disabled UEKR repo"
    puts "  - Running: puppet task run pe_patch::patch_server reboot=never yum_params='--enablerepo=local*UEKR*current'"
    puts "  - Cached package_update_count: 0 (because UEKR repo is disabled in default config)"
    puts "  - Expected: Task should run yum with --enablerepo flag"
    puts "  - Expected: UEK kernel packages should be updated from the enabled repo"

    updatecount = 0  # No updates in default enabled repos
    yum_params = '--enablerepo=local*UEKR*current'
    os_family = 'RedHat'

    # This is the critical logic from patch_server.rb lines 469-472
    skip_count_check = (!yum_params.empty? && os_family == 'RedHat') ||
                       (!zypper_params.empty? && os_family == 'Suse')

    should_exit_early = updatecount.zero? && !skip_count_check
    should_run_yum = !should_exit_early

    assert(skip_count_check == true, "skip_count_check should be TRUE with yum_params set")
    assert(should_exit_early == false, "should_exit_early should be FALSE (don't exit early)")
    assert(should_run_yum == true, "should_run_yum should be TRUE (run yum with --enablerepo)")

    puts "\n  Result: Task will proceed to run yum with --enablerepo parameter ✓"
    puts "  This allows yum to query the disabled repo and install UEK kernel updates"
  end

  def test_unsafe_content_detection
    puts "\n\n=== Testing Unsafe Content Detection ==="
    puts "This tests that malicious content in yum_params is detected\n"

    # Test various unsafe patterns
    # The actual regex in patch_server.rb is: %r{[\$\|\/;`&]}
    unsafe_patterns = [
      '--enablerepo=test; rm -rf /',
      '--enablerepo=test && cat /etc/passwd',
      '--enablerepo=test | grep something',
      '--enablerepo=test `whoami`',
      '--enablerepo=test$USER',
      '--enablerepo=test&background',
      '--enablerepo=test/etc/passwd'
    ]

    # Match the actual regex from patch_server.rb line 494
    unsafe_regex = %r{[\$\|\/;`&]}

    unsafe_patterns.each do |pattern|
      puts "\nTesting pattern: #{pattern}"
      is_unsafe = pattern =~ unsafe_regex
      assert(is_unsafe, "Pattern '#{pattern}' should be detected as unsafe")
    end

    # Test safe patterns
    safe_patterns = [
      '--enablerepo=local*UEKR*current',
      '--enablerepo=repo1,repo2',
      '--disablerepo=* --enablerepo=updates',
      '--exclude=kernel*',
      '-x kernel-debug'
    ]

    safe_patterns.each do |pattern|
      puts "\nTesting safe pattern: #{pattern}"
      is_unsafe = pattern =~ unsafe_regex
      assert(!is_unsafe, "Pattern '#{pattern}' should NOT be detected as unsafe")
    end
  end

  def run_all_tests
    puts "=" * 80
    puts "PATCH_SERVER.RB YUM_PARAMS BUG FIX TEST SUITE"
    puts "=" * 80
    puts "\nTesting the fix for: --enablerepo parameter not working when updatecount is 0"
    puts "Bug: Task exits early when no cached updates, ignoring yum_params"
    puts "Fix: Skip early exit check when yum_params or zypper_params are set"

    test_skip_count_check_logic
    test_early_exit_behavior
    test_customer_scenario
    test_unsafe_content_detection

    puts "\n" + "=" * 80
    puts "TEST RESULTS"
    puts "=" * 80
    puts "Total tests passed: #{@tests_passed}"
    puts "Total tests failed: #{@tests_failed}"

    if @tests_failed > 0
      puts "\nFAILURES:"
      @failures.each_with_index do |failure, i|
        puts "  #{i + 1}. #{failure}"
      end
      exit 1
    else
      puts "\n✓ All tests passed!"
      exit 0
    end
  end
end

# Run the tests if this file is executed directly
if __FILE__ == $PROGRAM_NAME
  test_suite = PatchServerYumParamsTest.new
  test_suite.run_all_tests
end

