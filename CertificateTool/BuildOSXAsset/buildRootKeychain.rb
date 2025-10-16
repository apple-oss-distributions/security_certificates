#!/usr/bin/env ruby -wKU
#
#  buildRootKeychain.rb
#  CertificateTool
#
#  Copyright 2012-2015 Apple Inc. All rights reserved.
#

require 'fileutils'
require 'singleton'
require 'cfpropertylist'

# =============================================================================
# Class:  Utilities
# 
# Description:  This class provides utility functions for the rest of the 
#               script.  
#
#               This is a singleton class meaning only one instance.
#               All of the methods are Class methods and are called by
#               Utilities.method_name  
# =============================================================================
class Utilities
  include Singleton

  # Provide a way to fail and die upon an error
  def self.bail(reason = nil)
    puts reason if !reason.nil?
    exit(-1)
  end

  # Check to see if a path is valid and possibly a directory
  def self.check_path(path, is_dir = true)
    Utilities.bail(path + " does not exist") if !FileTest.exist? path
    if is_dir
      Utilities.bail(path + " is not a directory") if !FileTest.directory? path
    end
    true
  end
  
  # Add quotes to a string.  This is useful for outputing file paths
  def self.quote_str(str)
    result = "'" + str + "'"
    result
  end

  # convert a hex string to binary
  def self.hex_to_bin(s)
    s.scan(/../).map { |x| x.hex.chr }.join
  end

  # convert a binary string to hex
  def self.bin_to_hex(s)
    s.each_byte.map { |b| b.to_s(16) }.join
  end

end

# =============================================================================
# Class:  CertTools
# 
# Description:  This class provides functions for getting required file paths
#               needed for this script.  It also provides support for saving
#               and restoring the keychain list and creating keychains.
#
#               This is a singleton class meaning only one instance.
#               All of the methods are Class methods and are called by
#               Utilities.method_name
# ==============================================================================
class CertTools
  include Singleton

  attr_reader :build_dir
  attr_reader :project_dir
  attr_reader :certificate_dir
  attr_reader :root_certs_dir
  attr_reader :intermediate_certs_dir
  attr_reader :security_tool_path
  attr_reader :output_keychain_path
  attr_writer :saved_kc_list

  # Initialize the single instance with the path strings needed by this script
  def initialize()
      
    @saved_kc_list = nil;
    @build_dir = ENV["BUILT_PRODUCTS_DIR"]
    @project_dir = ENV["PROJECT_DIR"]
    @certificate_dir = File.join(@project_dir, "../certificates")

    @root_certs_dir = File.join(certificate_dir, "roots")
    @intermediate_certs_dir = File.join(certificate_dir, "removed/intermediates")

    Utilities.check_path(@root_certs_dir)
    Utilities.check_path(@intermediate_certs_dir)

    @security_tool_path = '/usr/bin/security'
    Utilities.check_path(@security_tool_path, false)

    @output_keychain_path = File.join(@build_dir , "BuiltKeychains")
    FileUtils.mkdir_p(@output_keychain_path) if !FileTest.exist? @output_keychain_path
     
    output_variables = false
    if output_variables
      puts "================================================="
      puts "CertTools variables"
      puts " "
      puts "@build_dir = #{@build_dir}"
      puts "@project_dir = #{@project_dir}"
      puts "@certificate_dir = #{@certificate_dir}"
      puts "@root_certs_dir = #{@root_certs_dir}"
      puts "@intermediate_certs_dir = #{@intermediate_certs_dir}"
      puts "@security_tool_path = #{@security_tool_path}"
      puts "@output_keychain_path = #{@output_keychain_path}"
      puts "================================================="
      puts " "  
    end  
  end

  # Get the Build (output) directory path
  def self.build_dir
    CertTools.instance.build_dir
  end

  # Get the directory path to the top-level certificates directory
  def self.certificate_dir
    CertTools.instance.certificate_dir
  end

  # Get the directory path to the project directory
  def self.project_dir
    CertTools.instance.project_dir
  end

  # Get the directory path to the roots directory
  def self.root_certs_dir
    CertTools.instance.root_certs_dir
  end
  
  # Get the directory path to the intermediates directory
  def self.intermediate_certs_dir
    CertTools.instance.intermediate_certs_dir
  end

  # Get the path to the security tool
  def self.security_tool_path
    CertTools.instance.security_tool_path
  end

  # Get the directory path to the output directory for the generated keychains
  def self.output_keychain_path
    CertTools.instance.output_keychain_path
  end

  # Save the current keychain list
  def self.saveKeychainList()
    cmd_str = CertTools.instance.security_tool_path + " list -d user"
    temp =    `#{cmd_str}`
    CertTools.instance.saved_kc_list = temp
    $?
  end

  # Restore the keychain list from a previous call to saveKeychainList
  def self.restoreKeychainList()
    return if CertTools.instance.saved_kc_list.nil?
    st = CertTools.instance.security_tool_path
    cmd_str = "echo -n " +  Utilities.quote_str(CertTools.instance.saved_kc_list) + " |  xargs " + st + " list -d user -s"
    `#{cmd_str}`
    $?
  end

  # Create a new Keychain file
  def self.createKeychain(path, name)
    FileUtils.rm_rf(path) if FileTest.exist? path
    cmd_str = CertTools.security_tool_path + " create-keychain -p " + Utilities.quote_str(name) + " " +  Utilities.quote_str(path)
    `#{cmd_str}`
    $?
  end


end

# =============================================================================
# Class:  BuildRootKeychains
# 
# Description:  This class provides the necessary functionality to create the
#               SystemRootCertificates.keychain and the 
#               SystemTrustSettings.plist output files.
# =============================================================================
class BuildRootKeychains
  
  attr_reader :root_cert_file_name
  attr_reader :root_cert_kc_path
  attr_reader :settings_file_name
  attr_reader :setting_file_path
  attr_reader :temp_kc_name
  attr_reader :temp_kc_path

  
  attr        :verbose
  
  # Initialize this instance with the paths to the output files
  def initialize(verbose = true)
    @verbose = verbose
            
    @root_cert_file_name = "SystemRootCertificates.keychain"
    @root_cert_kc_path = File.join(CertTools.output_keychain_path, @root_cert_file_name)

    @settings_file_name = "SystemTrustSettings.plist"
    @setting_file_path = File.join(CertTools.output_keychain_path, @settings_file_name)

    @temp_kc_name = "SystemTempCertificates.keychain"
    @temp_kc_path = File.join(CertTools.build_dir, @temp_kc_name)

  end
  
  # Create the SystemRootCertificates.keychain
  def create_root_keychain()
    puts "Creating empty SystemRootCertificates keychain at #{@root_cert_kc_path}" if @verbose
    CertTools.createKeychain(@root_cert_kc_path, @root_cert_file_name)
  end

  # Create the SystemTrustSettings.plist file
  def create_setting_file()
    puts "Creating empty SystemTrustSettings file at #{@setting_file_path}" if @verbose
    FileUtils.rm_rf(@setting_file_path) if FileTest.exist? @setting_file_path
    cmd_str = CertTools.security_tool_path + " add-trusted-cert -o " + Utilities.quote_str(@setting_file_path)
    `#{cmd_str}`
    result = $?
    puts "security add-trusted-cert returned an error for #{setting_file_path}" if result != 0
    return result
  end

  # Add all of the root certificates in the root directory to the SystemRootCertificates.keychain
  def add_roots()
    puts "Adding root certs to #{@root_cert_file_name}" if @verbose
    num_root_certs = 0
    Dir.foreach(CertTools.root_certs_dir) do |f|
      next if f[0].chr == "."
      puts "Processing root #{f}" if @verbose
      full_root_path = File.join(CertTools.root_certs_dir, f)
      if f == "7AFC9D01A62F03A2DE9637936D4AFE68090D2DE18D03F29C88CFB0B1BA63587F.cer" # DevID CA
        puts " skipping intermediate #{f} for trust" if @verbose
        cmd_str = CertTools.security_tool_path + " -q add-certificates -k " + Utilities.quote_str(@root_cert_kc_path) + " " +
          Utilities.quote_str(full_root_path)

        `#{cmd_str}`
        Utilities.bail("security add-certificates returned an error for #{full_root_path}") if $? != 0
      else
        cmd_str =   CertTools.security_tool_path
        cmd_str +=  " -q add-trusted-cert -i "
        cmd_str +=  Utilities.quote_str(@setting_file_path)
        cmd_str +=   " -o "
        cmd_str +=  Utilities.quote_str(@setting_file_path)
        cmd_str +=  " -k "
        cmd_str +=  Utilities.quote_str(@root_cert_kc_path)
        cmd_str +=   " "
        cmd_str +=  Utilities.quote_str(full_root_path)
        cmd_result = `#{cmd_str}`
        Utilities.bail("security add-trusted-cert returned an error for #{full_root_path}") if $? != 0
        new_num_certs = get_num_root_certs
        if new_num_certs <= num_root_certs then
            puts "Root #{f} was not added! result = #{cmd_result.to_s}"
            puts cmd_str
        end
        num_root_certs = new_num_certs
      end
    end
    true
  end

  # Create a temp keychain needed by this script
  def create_temp_keychain()
   puts "Creating empty temp keychain at #{@temp_kc_path}" if @verbose 
   CertTools.createKeychain(@temp_kc_path, @temp_kc_name)
  end
  
  # Delete the temp keychain 
  def delete_temp_keychain()
    FileUtils.rm_rf(@temp_kc_path) if FileTest.exist? @temp_kc_path
  end

  # Process a directory of certificates that are not to be trusted.
  def process_certs(message, dir, deny = true)
    puts message if @verbose
    Dir.foreach(dir) do |f|
      next if f[0].chr == "."
      full_path = File.join(dir, f)
      #puts "Processing #{f}" if @verbose
      cmd_str =  CertTools.security_tool_path
      #cmd_str +=  " -q add-trusted-cert -i "
      cmd_str +=  " add-trusted-cert -i "
      cmd_str += Utilities.quote_str(@setting_file_path)
      cmd_str +=  " -o "
      cmd_str +=  Utilities.quote_str(@setting_file_path)
      cmd_str +=  " -k "
      cmd_str +=   Utilities.quote_str(@temp_kc_path)
      if deny
        cmd_str +=  " -r deny "
      else
        cmd_str +=  " -r unspecified "
      end
      cmd_str +=  Utilities.quote_str(full_path)
      `#{cmd_str}`
     Utilities.bail("security add-trusted-cert returned an error for #{full_path}") if $? != 0
    end
  end
  
  def get_num_root_certs()
      cmd_str =  CertTools.security_tool_path + " find-certificate -a " + Utilities.quote_str(@root_cert_kc_path)
      cert_str = `#{cmd_str}`
      Utilities.bail(" find-certificate failed")  if $? != 0
      cert_list = cert_str.split
      labl_list = cert_list.grep(/issu/)
      labl_list.length
  end

  # Ensure that all of the certs in the directory were added to the SystemRootCertificates.keychain file
  def check_all_roots_added()
      
      #cmd_str =  CertTools.security_tool_path + " find-certificate -a " + Utilities.quote_str(@root_cert_kc_path)
      #cert_str = `#{cmd_str}`
      #Utilities.bail(" find-certificate failed")  if $? != 0
      #cert_list = cert_str.split
      #labl_list = cert_list.grep(/labl/)
      #num_items_in_kc = labl_list.length
    num_items_in_kc = get_num_root_certs
    
    file_system_entries = Dir.entries(CertTools.root_certs_dir)
    num_file_system_entries = file_system_entries.length
    file_system_entries.each do |f| 
      if f[0].chr == "."  
        num_file_system_entries = num_file_system_entries - 1
      end
     end
     
    puts "num_items_in_kc = #{num_items_in_kc}" if @verbose 
    puts "num_file_system_entries = #{num_file_system_entries}" if @verbose 
    num_items_in_kc == num_file_system_entries
  end

  # Set the file access for the SystemRootCertificates.keychain and 
  # SystemTrustSettings.plist files
  def set_file_priv()
    FileUtils.chmod 0644, @setting_file_path
    FileUtils.chmod 0644, @root_cert_kc_path
  end

  # Do all of the processing to create the SystemRootCertificates.keychain and 
  # SystemTrustSettings.plist files
  def do_processing()
    result = create_root_keychain
    Utilities.bail("create_root_keychain failed")  if result != 0
    result = create_setting_file
    Utilities.bail("create_setting_file failed") if result != 0
    add_roots()
    Utilities.bail("create_temp_keychain failed") if create_temp_keychain != 0
    delete_temp_keychain()
    Utilities.bail("check_all_roots_added failed") if !check_all_roots_added
    set_file_priv()
  end
end

# =============================================================================
# Class:  BuildCAKeychain
# 
# Description:  This class provides the necessary functionality to create the
#               SystemCACertificates.keychain output file.
# OBSOLETE
# SystemCACertificates.keychain file is no longer generated: rdar://14206237
# =============================================================================
class BuildCAKeychain
  
  attr_reader :cert_kc_name
  attr_reader :cert_kc_path
  
  attr        :verbose
  
  # Initialize the output path for this instance
  def initialize(verbose = true)
    @verbose = verbose
      
    @cert_kc_name = "SystemCACertificates.keychain"
    @cert_kc_path = File.join(CertTools.output_keychain_path, @cert_kc_name)
  end
  
      
  # Add all of the certificates in the certs directory to the 
  # SystemCACertificates.keychain file
  def do_processing()
    CertTools.createKeychain(@cert_kc_path, @cert_kc_name)
    cert_path = CertTools.intermediate_certs_dir
    
    puts "Adding intermediate certs to #{@cert_kc_path}" if @verbose
    puts "Intermediates #{cert_path}" if @verbose 
    
    Dir.foreach(cert_path) do |f|
      next if f[0].chr == "."
      full_path = File.join(cert_path, f)
      puts "Processing #{f}" if @verbose
      cmd_str =  CertTools.security_tool_path
      cmd_str +=  " -q add-certificates "
      cmd_str +=  " -k "
      cmd_str +=   Utilities.quote_str(@cert_kc_path)
      cmd_str +=  " "
      cmd_str +=  Utilities.quote_str(full_path)
      `#{cmd_str}`
      Utilities.bail("security add-certificates returned an error for #{full_path}") if $? != 0
    end
   
   FileUtils.chmod 0644, @cert_kc_path
  end  
end
  
  
# =============================================================================
# Class:  BuildEVRoots
# 
# Description:  This class provides the necessary functionality to create the
#               EVRoots.plist output file.
# OBSOLETE
# EVRoots.plist has been built by the BuildiOSAsset target for many years
# =============================================================================
class BuildEVRoots
  attr_reader :open_ssl_tool_path
  attr_reader :plistbuddy_tool_path
  attr_reader :evroots_kc_name
  attr_reader :evroots_kc_path
  attr_reader :evroots_plist_name
  attr_reader :evroots_plist_path
  attr_reader :evroots_config_path
  attr_reader :sha1_filepath

  attr        :verbose
  attr        :evroots_config_data

  # Initialize this instance with the paths to the openssl and PlistBuddy tools
  # along with the output paths for the EVRoots.keychain and EVRoots.plist files
  #
  # The use of the openssl and PListBuddy tools should be removed.  These were
  # kept to ensure that the outputs between this new script and the original 
  # shell scripts remain the same
  def initialize(verbose = true)

    @verbose = verbose

    @open_ssl_tool_path = "/usr/bin/openssl"
    @plistbuddy_tool_path = "/usr/libexec/PlistBuddy"
    @evroots_config_path = File.join(CertTools.certificate_dir, "evroot.config")
    @evroots_config_data = nil

    Utilities.check_path(@evroots_config_path, false)

    @evroots_kc_name = "EVRoots.keychain"
    @evroots_kc_path = File.join(CertTools.build_dir, @evroots_kc_name)

    @evroots_plist_name = "EVRoots.plist"
    @evroots_plist_path = File.join(CertTools.output_keychain_path, @evroots_plist_name)

    @sha1_filepath = File.join(CertTools.build_dir, "certsha1hashtmp")

  end
  
  # Get and cache the data in the evroot.config file.
  def get_config_data()
    return @evroots_config_data if !@evroots_config_data.nil?
    
    @evroots_config_data = ""
    File.open(@evroots_config_path, "r") do |file|
      file.each do |line|
        line.gsub!(/^#.*\n/, '')
        next if line.empty?
        line.gsub!(/^\s*\n/, '')
        next if line.empty?
        @evroots_config_data += line
      end
    end
    @evroots_config_data
  end
  
  # Break the string from the get_config_data method into an array of lines.
  def get_cert_lines()
    lines_str = get_config_data
    lines = lines_str.split("\n")
    lines
  end
 
  # The processing for the EVRoots.plist requires two passes.  This first pass
  # adds the certs in the evroot.config file to the EVRoots.keychain
  def pass_one()    
    lines = get_cert_lines
    lines.each do |line|
      items = line.split('"')
      items.shift
      items.each do |cert_file|
        next if cert_file.empty? ||  cert_file == " "
        cert_file.gsub!(/\"/, '')
        puts "Adding cert from file #{cert_file}" if @verbose
        cert_to_add = File.join(CertTools.root_certs_dir, cert_file)
        Utilities.bail("#{cert_to_add} does not exist") if !FileTest.exist?(cert_to_add)

        quoted_cert_to_add = Utilities.quote_str(cert_to_add)
        cmd_str = CertTools.security_tool_path + " -q add-certificates -k " + @evroots_kc_path + " " + quoted_cert_to_add
        `#{cmd_str}`
        Utilities.bail("#{cmd_str} failed") if $? != 0 && $? != 256
      end  # items.each do |cert_file| 
    end  # lines.each do |line|   
  end

  # The second pass does the work to create the EVRoots.plist
  def pass_two()
    lines = get_cert_lines
    lines.sort!

    # For each line in the evroot.config each certs will be added to the CAB Forum oid string.
    # This is supported by adding an array in the EVRoots.plist.
    generic_cert_list = Array.new
    output = Hash.new

    lines.each do |line|
      # Split the line using a double quote.  This is needed to ensure that file names with spaces work
      items = line.split('"')
      
      # Get the oid string which is the first item in the array.
      oid_str = items.shift
      oid_str.gsub!(/\s/, '')

      cert_list = Array.new

      # Loop through all of the cert file names in the line.
      items.each do |cert_file|
        # Get the full path to the cert file.
        next if cert_file.empty? ||  cert_file == " "
        cert_file.gsub!(/\"/, '')
        cert_to_hash = File.join(CertTools.root_certs_dir, cert_file)
        Utilities.bail("#{cert_to_hash} does not exist") if !FileTest.exist?(cert_to_hash)

        # Use the openssl command line tool to get the fingerprint of the certificate
        cmd_str = @open_ssl_tool_path + " x509 -inform DER -in " + Utilities.quote_str(cert_to_hash) + " -fingerprint -noout"
        finger_print = `#{cmd_str}`
        Utilities.bail("#{cmd_str} failed") if $? != 0

        # Post process the data from the openssl tool to get just the hex hash fingerprint.
        finger_print.gsub!(/SHA1 Fingerprint=/, '')
        finger_print.gsub!(/:/,'').chomp!
        puts "Certificate fingerprint for #{cert_file} SHA1: #{finger_print}" if @verbose

        # Convert the hex hash string to binary data and write that data out to a temp file
        binary_finger_print = Utilities.hex_to_bin(finger_print)
        output_finger_print = CFPropertyList::Blob.new(binary_finger_print)

        cert_list << output_finger_print

        if !generic_cert_list.include? output_finger_print
          generic_cert_list << output_finger_print
        end
        
      end # items.each do |cert_file|

      # add the vendor-specifc OID to cert hashes map to the output dictionary
      output[oid_str] = cert_list

    end # lines.each do |line|

    # add the generic CABF OID to all cert hashes map to the output dictionary
    output["2.23.140.1.1"] = generic_cert_list

    # write the plist to disk
    plist = output.to_plist({:plist_format => CFPropertyList::List::FORMAT_XML, :formatted => true})
    File.open( @evroots_plist_path, "w") { |f| f.write plist }

  end # def pass_two()

  # Do all of the necessary work for this class
  def do_processing()
    CertTools.saveKeychainList
    CertTools.createKeychain(@evroots_kc_path, @evroots_kc_name)
    pass_one 
    puts "Removing #{@evroots_plist_path}" if @verbose 
    FileUtils.rm_f @evroots_plist_path 
    pass_two
    FileUtils.chmod 0644, @evroots_plist_path 
    puts "Built #{@evroots_plist_path} successfully" if @verbose
  end

end

# Make the SystemRootCertificates.keychain and SystemTrustSettings.plist files

# To get verbose logging set this true, otherwise false
verbose = true;

brkc = BuildRootKeychains.new(verbose)
brkc.do_processing

# Make the SystemCACertificates.keychain file
# OBSOLETE
# SystemCACertificates.keychain file is no longer generated: rdar://14206237
#bcakc = BuildCAKeychain.new(verbose)
#bcakc.do_processing

# Make the EVRoots.plist file
# OBSOLETE
#bevr = BuildEVRoots.new(verbose)
#bevr.do_processing

# M I C R O S O F T  H A C K !
# It turns out that the Mac Office (2008) rolled their own solution to roots.
# The X509Anchors file used to hold the roots in old versions of OSX.  This was
# an implementation detail and was NOT part of the API set.  Unfortunately, 
# Microsoft used the keychain directly instead of using the supplied APIs.  When
# the X509Anchors file was removed, it broke Mac Office.  So this file is now
# supplied to keep Office from breaking.  It is NEVER updated and there is no
# code to update this file.  We REALLY should see if this is still necessary
x509_anchors_path = File.join(CertTools.project_dir, "BuildOSXAsset/X509Anchors")
output_dir = File.join(CertTools.output_keychain_path, "X509Anchors")
FileUtils.cp x509_anchors_path, output_dir

puts "Root store processing complete"
