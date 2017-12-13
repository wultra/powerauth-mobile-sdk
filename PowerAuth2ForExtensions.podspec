Pod::Spec.new do |s|
	# General information
	s.name              = 'PowerAuth2ForExtensions'
	s.version           = '0.1.0'
	s.summary           = 'PowerAuth 2.0 Mobile SDK for iOS Extensions'
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
		:submodules => false
	}
	
	# Library validation & build
	s.platform        = :ios, '8.0'
	s.prepare_command = <<-CMD
		./scripts/ios-extensions-build.sh --out-dir Library ios
	CMD
	
	# Produced files
	s.source_files          = 'Library/**/*.{h,m}'
	s.requires_arc          = true
	s.compiler_flags        = '-DPA2_EXTENSION_SDK=1'
	s.framework             = 'Security'
	
end