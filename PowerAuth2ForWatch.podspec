Pod::Spec.new do |s|
	# General information
	s.name              = 'PowerAuth2ForWatch'
	s.version           = '0.18.2'
	s.summary           = 'PowerAuth 2.0 Mobile SDK for watchOS'
	s.homepage          = 'https://github.com/lime-company/powerauth-mobile-sdk'
	s.social_media_url  = 'https://twitter.com/lime_company'
	s.documentation_url = 'https://github.com/lime-company/powerauth-mobile-sdk/wiki/PowerAuth-SDK-for-watchOS'
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
		# submodules => false is enough, but we're using the same git repo as PA2 and cocoapods 
		# doesn't like when the same repo is cloned without and then with sumbodules...
		:submodules => true
	}
	
	# Library validation & build
	s.platform        = :watchos, '2.0'
	s.prepare_command = <<-CMD
		./scripts/ios-extensions-build.sh --out-dir Build release watchos
	CMD
	
	# Produced files
	s.vendored_frameworks   = 'Build/PowerAuth2ForWatch.framework'
	
end
