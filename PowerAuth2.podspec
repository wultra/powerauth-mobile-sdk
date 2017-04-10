Pod::Spec.new do |s|
	# General information
	s.name				    	= 'PowerAuth2'
	s.version				    = '0.12.0'
	s.summary				    = 'PowerAuth 2.0 Mobile SDK for iOS.'
	s.homepage    		  = 'https://powerauth.com'
	s.social_media_url  = 'https://twitter.com/lime_company'
	s.author          	= { 'Lime - HighTech Solution s.r.o.' => 'support@lime-company.eu' }
	s.license    		  	= { 
		:type => 'Apache License, Version 2.0', 
		:file => 'LICENSE' 
	}
		
	# Source files
	s.source		      	= { 
		:git => 'https://github.com/lime-company/lime-security-powerauth-mobile-sdk.git',
		:tag => "#{s.version}",
		:submodules => true
	}
	
	# FAT library build
	s.platform    			= :ios, '8.0'
	s.prepare_command 	= <<-CMD
		./proj-xcode/build-libraries.sh release --lib-dir Library --hdr-dir Library
	CMD
	
	# Produced files
	s.source_files			    = 'Library/**/*.h'
	s.public_header_files	  = 'Library/**/*.h'
	s.vendored_libraries	  = 'Library/libPowerAuth2.a'
	s.requires_arc			    = true
	s.libraries 			      = 'c++'
	
end