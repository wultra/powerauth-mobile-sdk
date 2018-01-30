Pod::Spec.new do |s|
	# General information
	s.name              = 'PowerAuth2'
	s.version           = '%DEPLOY_VERSION%'
	s.summary           = 'PowerAuth 2.0 Mobile SDK for iOS'
	s.homepage          = 'https://github.com/lime-company/powerauth-mobile-sdk'
	s.social_media_url  = 'https://twitter.com/lime_company'
	s.documentation_url = 'https://github.com/lime-company/powerauth-mobile-sdk/wiki/PowerAuth-SDK-for-iOS'
	s.author            = { 
	  'Lime - HighTech Solution s.r.o.' => 'support@lime-company.eu'
	}
	s.license = { 
		:type => 'Apache License, Version 2.0', 
		:file => 'LICENSE' 
	}
		
	# Source files
	s.source = { 
		:git => 'https://github.com/lime-company/powerauth-mobile-sdk.git',
		:tag => "#{s.version}",
		:submodules => true
	}
	
	# FAT framework build
	s.platform        = :ios, '8.0'
	s.prepare_command = <<-CMD
		./scripts/ios-build-libraries.sh release --out-dir Library
	CMD
	
	# Produced files
  s.vendored_frameworks   = 'Library/PowerAuth2.framework'
  s.libraries             = 'c++'
	
end
